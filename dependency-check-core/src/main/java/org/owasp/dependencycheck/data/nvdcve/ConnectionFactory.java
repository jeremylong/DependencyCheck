/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.owasp.dependencycheck.utils.DBUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads the configured database driver and returns the database connection. If the embedded H2 database is used obtaining a
 * connection will ensure the database file exists and that the appropriate table structure has been created.
 *
 * @author Jeremy Long
 */
public final class ConnectionFactory {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionFactory.class);
    /**
     * The version of the current DB Schema.
     */
    public static final String DB_SCHEMA_VERSION = Settings.getString(Settings.KEYS.DB_VERSION);
    /**
     * Resource location for SQL file used to create the database schema.
     */
    public static final String DB_STRUCTURE_RESOURCE = "data/initialize.sql";
    /**
     * Resource location for SQL file used to create the database schema.
     */
    public static final String DB_STRUCTURE_UPDATE_RESOURCE = "data/upgrade_%s.sql";
    /**
     * The database driver used to connect to the database.
     */
    private static Driver driver = null;
    /**
     * The database connection string.
     */
    private static String connectionString = null;
    /**
     * The username to connect to the database.
     */
    private static String userName = null;
    /**
     * The password for the database.
     */
    private static String password = null;

    /**
     * Private constructor for this factory class; no instance is ever needed.
     */
    private ConnectionFactory() {
    }

    /**
     * Initializes the connection factory. Ensuring that the appropriate drivers are loaded and that a connection can be made
     * successfully.
     *
     * @throws DatabaseException thrown if we are unable to connect to the database
     */
    public static synchronized void initialize() throws DatabaseException {
        //this only needs to be called once.
        if (connectionString != null) {
            return;
        }
        Connection conn = null;
        try {
            //load the driver if necessary
            final String driverName = Settings.getString(Settings.KEYS.DB_DRIVER_NAME, "");
            if (!driverName.isEmpty()) { //likely need to load the correct driver
                LOGGER.debug("Loading driver: {}", driverName);
                final String driverPath = Settings.getString(Settings.KEYS.DB_DRIVER_PATH, "");
                try {
                    if (!driverPath.isEmpty()) {
                        LOGGER.debug("Loading driver from: {}", driverPath);
                        driver = DriverLoader.load(driverName, driverPath);
                    } else {
                        driver = DriverLoader.load(driverName);
                    }
                } catch (DriverLoadException ex) {
                    LOGGER.debug("Unable to load database driver", ex);
                    throw new DatabaseException("Unable to load database driver");
                }
            }
            userName = Settings.getString(Settings.KEYS.DB_USER, "dcuser");
            //yes, yes - hard-coded password - only if there isn't one in the properties file.
            password = Settings.getString(Settings.KEYS.DB_PASSWORD, "DC-Pass1337!");
            try {
                connectionString = Settings.getConnectionString(
                        Settings.KEYS.DB_CONNECTION_STRING,
                        Settings.KEYS.DB_FILE_NAME);
            } catch (IOException ex) {
                LOGGER.debug(
                        "Unable to retrieve the database connection string", ex);
                throw new DatabaseException("Unable to retrieve the database connection string");
            }
            boolean shouldCreateSchema = false;
            try {
                if (connectionString.startsWith("jdbc:h2:file:")) { //H2
                    shouldCreateSchema = !h2DataFileExists();
                    LOGGER.debug("Need to create DB Structure: {}", shouldCreateSchema);
                }
            } catch (IOException ioex) {
                LOGGER.debug("Unable to verify database exists", ioex);
                throw new DatabaseException("Unable to verify database exists");
            }
            LOGGER.debug("Loading database connection");
            LOGGER.debug("Connection String: {}", connectionString);
            LOGGER.debug("Database User: {}", userName);

            try {
                conn = DriverManager.getConnection(connectionString, userName, password);
            } catch (SQLException ex) {
                if (ex.getMessage().contains("java.net.UnknownHostException") && connectionString.contains("AUTO_SERVER=TRUE;")) {
                    connectionString = connectionString.replace("AUTO_SERVER=TRUE;", "");
                    try {
                        conn = DriverManager.getConnection(connectionString, userName, password);
                        Settings.setString(Settings.KEYS.DB_CONNECTION_STRING, connectionString);
                        LOGGER.debug(
                                "Unable to start the database in server mode; reverting to single user mode");
                    } catch (SQLException sqlex) {
                        LOGGER.debug("Unable to connect to the database", ex);
                        throw new DatabaseException("Unable to connect to the database");
                    }
                } else {
                    LOGGER.debug("Unable to connect to the database", ex);
                    throw new DatabaseException("Unable to connect to the database");
                }
            }

            if (shouldCreateSchema) {
                try {
                    createTables(conn);
                } catch (DatabaseException dex) {
                    LOGGER.debug("", dex);
                    throw new DatabaseException("Unable to create the database structure");
                }
            }
            try {
                ensureSchemaVersion(conn);
            } catch (DatabaseException dex) {
                LOGGER.debug("", dex);
                throw new DatabaseException("Database schema does not match this version of dependency-check", dex);
            }
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException ex) {
                    LOGGER.debug("An error occurred closing the connection", ex);
                }
            }
        }
    }

    /**
     * Cleans up resources and unloads any registered database drivers. This needs to be called to ensure the driver is
     * unregistered prior to the finalize method being called as during shutdown the class loader used to load the driver may be
     * unloaded prior to the driver being de-registered.
     */
    public static synchronized void cleanup() {
        if (driver != null) {
            try {
                DriverManager.deregisterDriver(driver);
            } catch (SQLException ex) {
                LOGGER.debug("An error occurred unloading the database driver", ex);
            } catch (Throwable unexpected) {
                LOGGER.debug(
                        "An unexpected throwable occurred unloading the database driver", unexpected);
            }
            driver = null;
        }
        connectionString = null;
        userName = null;
        password = null;
    }

    /**
     * Constructs a new database connection object per the database configuration.
     *
     * @return a database connection object
     * @throws DatabaseException thrown if there is an exception loading the database connection
     */
    public static Connection getConnection() throws DatabaseException {
        initialize();
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(connectionString, userName, password);
        } catch (SQLException ex) {
            LOGGER.debug("", ex);
            throw new DatabaseException("Unable to connect to the database");
        }
        return conn;
    }

    /**
     * Determines if the H2 database file exists. If it does not exist then the data structure will need to be created.
     *
     * @return true if the H2 database file does not exist; otherwise false
     * @throws IOException thrown if the data directory does not exist and cannot be created
     */
    private static boolean h2DataFileExists() throws IOException {
        final File dir = Settings.getDataDirectory();
        final String fileName = Settings.getString(Settings.KEYS.DB_FILE_NAME);
        final File file = new File(dir, fileName);
        return file.exists();
    }

    /**
     * Creates the database structure (tables and indexes) to store the CVE data.
     *
     * @param conn the database connection
     * @throws DatabaseException thrown if there is a Database Exception
     */
    private static void createTables(Connection conn) throws DatabaseException {
        LOGGER.debug("Creating database structure");
        InputStream is;
        InputStreamReader reader;
        BufferedReader in = null;
        try {
            is = ConnectionFactory.class.getClassLoader().getResourceAsStream(DB_STRUCTURE_RESOURCE);
            reader = new InputStreamReader(is, "UTF-8");
            in = new BufferedReader(reader);
            final StringBuilder sb = new StringBuilder(2110);
            String tmp;
            while ((tmp = in.readLine()) != null) {
                sb.append(tmp);
            }
            Statement statement = null;
            try {
                statement = conn.createStatement();
                statement.execute(sb.toString());
            } catch (SQLException ex) {
                LOGGER.debug("", ex);
                throw new DatabaseException("Unable to create database statement", ex);
            } finally {
                DBUtils.closeStatement(statement);
            }
        } catch (IOException ex) {
            throw new DatabaseException("Unable to create database schema", ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOGGER.trace("", ex);
                }
            }
        }
    }

    /**
     * Updates the database schema by loading the upgrade script for the version specified. The intended use is that if the
     * current schema version is 2.9 then we would call updateSchema(conn, "2.9"). This would load the upgrade_2.9.sql file and
     * execute it against the database. The upgrade script must update the 'version' in the properties table.
     *
     * @param conn the database connection object
     * @param schema the current schema version that is being upgraded
     * @throws DatabaseException thrown if there is an exception upgrading the database schema
     */
    private static void updateSchema(Connection conn, String schema) throws DatabaseException {
        LOGGER.debug("Updating database structure");
        InputStream is;
        InputStreamReader reader;
        BufferedReader in = null;
        String updateFile = null;
        try {
            updateFile = String.format(DB_STRUCTURE_UPDATE_RESOURCE, schema);
            is = ConnectionFactory.class.getClassLoader().getResourceAsStream(updateFile);
            if (is == null) {
                throw new DatabaseException(String.format("Unable to load update file '%s'", updateFile));
            }
            reader = new InputStreamReader(is, "UTF-8");
            in = new BufferedReader(reader);
            final StringBuilder sb = new StringBuilder(2110);
            String tmp;
            while ((tmp = in.readLine()) != null) {
                sb.append(tmp);
            }
            Statement statement = null;
            try {
                statement = conn.createStatement();
                statement.execute(sb.toString());
            } catch (SQLException ex) {
                LOGGER.debug("", ex);
                throw new DatabaseException("Unable to update database schema", ex);
            } finally {
                DBUtils.closeStatement(statement);
            }
        } catch (IOException ex) {
            final String msg = String.format("Upgrade SQL file does not exist: %s", updateFile);
            throw new DatabaseException(msg, ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOGGER.trace("", ex);
                }
            }
        }
    }

    /**
     * Uses the provided connection to check the specified schema version within the database.
     *
     * @param conn the database connection object
     * @throws DatabaseException thrown if the schema version is not compatible with this version of dependency-check
     */
    private static void ensureSchemaVersion(Connection conn) throws DatabaseException {
        ResultSet rs = null;
        CallableStatement cs = null;
        try {
            //TODO convert this to use DatabaseProperties
            cs = conn.prepareCall("SELECT value FROM properties WHERE id = 'version'");
            rs = cs.executeQuery();
            if (rs.next()) {
                if (!DB_SCHEMA_VERSION.equals(rs.getString(1))) {
                    LOGGER.error("Current Schema: " + DB_SCHEMA_VERSION);
                    LOGGER.error("DB Schema: " + rs.getString(1));
                    LOGGER.error("-------------------------------------------------------\n\n\n\n\nUpdating from version: " + rs.getString(1) + "\n\n\n\n\n---------------------------------------------------------------------------------");
                    updateSchema(conn, rs.getString(1));
                }
            } else {
                throw new DatabaseException("Database schema is missing");
            }
        } catch (SQLException ex) {
            LOGGER.debug("", ex);
            throw new DatabaseException("Unable to check the database schema version");
        } finally {
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(cs);
        }
    }
}
