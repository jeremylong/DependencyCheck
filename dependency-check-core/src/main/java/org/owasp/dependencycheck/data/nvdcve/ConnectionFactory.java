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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.utils.DBUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Loads the configured database driver and returns the database connection. If the embedded H2 database is used
 * obtaining a connection will ensure the database file exists and that the appropriate table structure has been
 * created.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class ConnectionFactory {
    /**
     * The Logger.
     */
    private static final Logger LOGGER = Logger.getLogger(ConnectionFactory.class.getName());
    /**
     * The version of the current DB Schema.
     */
    public static final String DB_SCHEMA_VERSION = "2.9";
    /**
     * Resource location for SQL file used to create the database schema.
     */
    public static final String DB_STRUCTURE_RESOURCE = "data/initialize.sql";
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
     * Initializes the connection factory. Ensuring that the appropriate drivers are loaded and that a connection can be
     * made successfully.
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
                LOGGER.log(Level.FINE, "Loading driver: {0}", driverName);
                final String driverPath = Settings.getString(Settings.KEYS.DB_DRIVER_PATH, "");
                try {
                    if (!driverPath.isEmpty()) {
                        LOGGER.log(Level.FINE, "Loading driver from: {0}", driverPath);
                        driver = DriverLoader.load(driverName, driverPath);
                    } else {
                        driver = DriverLoader.load(driverName);
                    }
                } catch (DriverLoadException ex) {
                    LOGGER.log(Level.FINE, "Unable to load database driver", ex);
                    throw new DatabaseException("Unable to load database driver");
                }
            }
            userName = Settings.getString(Settings.KEYS.DB_USER, "dcuser");
            //yes, yes - hard-coded password - only if there isn't one in the properties file.
            password = Settings.getString(Settings.KEYS.DB_PASSWORD, "DC-Pass1337!");
            try {
                connectionString = getConnectionString();
            } catch (IOException ex) {
                LOGGER.log(Level.FINE,
                        "Unable to retrieve the database connection string", ex);
                throw new DatabaseException("Unable to retrieve the database connection string");
            }
            boolean shouldCreateSchema = false;
            try {
                if (connectionString.startsWith("jdbc:h2:file:")) { //H2
                    shouldCreateSchema = !dbSchemaExists();
                    LOGGER.log(Level.FINE, "Need to create DB Structure: {0}", shouldCreateSchema);
                }
            } catch (IOException ioex) {
                LOGGER.log(Level.FINE, "Unable to verify database exists", ioex);
                throw new DatabaseException("Unable to verify database exists");
            }
            LOGGER.log(Level.FINE, "Loading database connection");
            LOGGER.log(Level.FINE, "Connection String: {0}", connectionString);
            LOGGER.log(Level.FINE, "Database User: {0}", userName);

            try {
                conn = DriverManager.getConnection(connectionString, userName, password);
            } catch (SQLException ex) {
                if (ex.getMessage().contains("java.net.UnknownHostException") && connectionString.contains("AUTO_SERVER=TRUE;")) {
                    connectionString = connectionString.replace("AUTO_SERVER=TRUE;", "");
                    try {
                        conn = DriverManager.getConnection(connectionString, userName, password);
                        Settings.setString(Settings.KEYS.DB_CONNECTION_STRING, connectionString);
                        LOGGER.log(Level.FINE,
                                "Unable to start the database in server mode; reverting to single user mode");
                    } catch (SQLException sqlex) {
                        LOGGER.log(Level.FINE, "Unable to connect to the database", ex);
                        throw new DatabaseException("Unable to connect to the database");
                    }
                } else {
                    LOGGER.log(Level.FINE, "Unable to connect to the database", ex);
                    throw new DatabaseException("Unable to connect to the database");
                }
            }

            if (shouldCreateSchema) {
                try {
                    createTables(conn);
                } catch (DatabaseException dex) {
                    LOGGER.log(Level.FINE, null, dex);
                    throw new DatabaseException("Unable to create the database structure");
                }
            } else {
                try {
                    ensureSchemaVersion(conn);
                } catch (DatabaseException dex) {
                    LOGGER.log(Level.FINE, null, dex);
                    throw new DatabaseException("Database schema does not match this version of dependency-check");
                }
            }
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException ex) {
                    LOGGER.log(Level.FINE, "An error occured closing the connection", ex);
                }
            }
        }
    }

    /**
     * Cleans up resources and unloads any registered database drivers. This needs to be called to ensure the driver is
     * unregistered prior to the finalize method being called as during shutdown the class loader used to load the
     * driver may be unloaded prior to the driver being de-registered.
     */
    public static synchronized void cleanup() {
        if (driver != null) {
            try {
                DriverManager.deregisterDriver(driver);
            } catch (SQLException ex) {
                LOGGER.log(Level.FINE, "An error occured unloading the databse driver", ex);
            } catch (Throwable unexpected) {
                LOGGER.log(Level.FINE,
                        "An unexpected throwable occured unloading the databse driver", unexpected);
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
            LOGGER.log(Level.FINE, null, ex);
            throw new DatabaseException("Unable to connect to the database");
        }
        return conn;
    }

    /**
     * Returns the configured connection string. If using the embedded H2 database this function will also ensure the
     * data directory exists and if not create it.
     *
     * @return the connection string
     * @throws IOException thrown the data directory cannot be created
     */
    private static String getConnectionString() throws IOException {
        final String connStr = Settings.getString(Settings.KEYS.DB_CONNECTION_STRING, "jdbc:h2:file:%s;AUTO_SERVER=TRUE");
        if (connStr.contains("%s")) {
            final String directory = getDataDirectory().getCanonicalPath();
            final File dataFile = new File(directory, "cve." + DB_SCHEMA_VERSION);
            LOGGER.log(Level.FINE, String.format("File path for H2 file: '%s'", dataFile.toString()));
            return String.format(connStr, dataFile.getAbsolutePath());
        }
        return connStr;
    }

    /**
     * Retrieves the directory that the JAR file exists in so that we can ensure we always use a common data directory
     * for the embedded H2 database. This is public solely for some unit tests; otherwise this should be private.
     *
     * @return the data directory to store data files
     * @throws IOException is thrown if an IOException occurs of course...
     */
    public static File getDataDirectory() throws IOException {
        final File path = Settings.getDataFile(Settings.KEYS.DATA_DIRECTORY);
        if (!path.exists()) {
            if (!path.mkdirs()) {
                throw new IOException("Unable to create NVD CVE Data directory");
            }
        }
        return path;
    }

    /**
     * Determines if the H2 database file exists. If it does not exist then the data structure will need to be created.
     *
     * @return true if the H2 database file does not exist; otherwise false
     * @throws IOException thrown if the data directory does not exist and cannot be created
     */
    private static boolean dbSchemaExists() throws IOException {
        final File dir = getDataDirectory();
        final String name = String.format("cve.%s.h2.db", DB_SCHEMA_VERSION);
        final File file = new File(dir, name);
        return file.exists();
    }

    /**
     * Creates the database structure (tables and indexes) to store the CVE data.
     *
     * @param conn the database connection
     * @throws DatabaseException thrown if there is a Database Exception
     */
    private static void createTables(Connection conn) throws DatabaseException {
        LOGGER.log(Level.FINE, "Creating database structure");
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
                LOGGER.log(Level.FINE, null, ex);
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
                    LOGGER.log(Level.FINEST, null, ex);
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
            cs = conn.prepareCall("SELECT value FROM properties WHERE id = 'version'");
            rs = cs.executeQuery();
            if (rs.next()) {
                final boolean isWrongSchema = !DB_SCHEMA_VERSION.equals(rs.getString(1));
                if (isWrongSchema) {
                    throw new DatabaseException("Incorrect database schema; unable to continue");
                }
            } else {
                throw new DatabaseException("Database schema is missing");
            }
        } catch (SQLException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new DatabaseException("Unable to check the database schema version");
        } finally {
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(cs);
        }
    }
}
