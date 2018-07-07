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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.io.IOUtils;
import org.owasp.dependencycheck.utils.DBUtils;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads the configured database driver and returns the database connection. If
 * the embedded H2 database is used obtaining a connection will ensure the
 * database file exists and that the appropriate table structure has been
 * created.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class ConnectionFactory {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionFactory.class);
    /**
     * Resource location for SQL file used to create the database schema.
     */
    public static final String DB_STRUCTURE_RESOURCE = "data/initialize.sql";
    /**
     * Resource location for SQL file used to create the database schema.
     */
    public static final String DB_STRUCTURE_UPDATE_RESOURCE = "data/upgrade_%s.sql";
    /**
     * The URL that discusses upgrading non-H2 databases.
     */
    public static final String UPGRADE_HELP_URL = "http://jeremylong.github.io/DependencyCheck/data/upgrade.html";
    /**
     * The database driver used to connect to the database.
     */
    private Driver driver = null;
    /**
     * The database connection string.
     */
    private String connectionString = null;
    /**
     * The username to connect to the database.
     */
    private String userName = null;
    /**
     * The password for the database.
     */
    private String password = null;
    /**
     * Counter to ensure that calls to ensureSchemaVersion does not end up in an
     * endless loop.
     */
    private int callDepth = 0;
    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * Private constructor for this factory class; no instance is ever needed.
     *
     * @param settings the configured settings
     */
    public ConnectionFactory(Settings settings) {
        this.settings = settings;
    }

    /**
     * Initializes the connection factory. Ensuring that the appropriate drivers
     * are loaded and that a connection can be made successfully.
     *
     * @throws DatabaseException thrown if we are unable to connect to the
     * database
     */
    public synchronized void initialize() throws DatabaseException {
        //this only needs to be called once.
        if (connectionString != null) {
            return;
        }
        Connection conn = null;
        try {
            //load the driver if necessary
            final String driverName = settings.getString(Settings.KEYS.DB_DRIVER_NAME, "");
            final String driverPath = settings.getString(Settings.KEYS.DB_DRIVER_PATH, "");
            LOGGER.debug("Loading driver '{}'", driverName);
            try {
                if (!driverPath.isEmpty()) {
                    LOGGER.debug("Loading driver from: {}", driverPath);
                    driver = DriverLoader.load(driverName, driverPath);
                } else {
                    driver = DriverLoader.load(driverName);
                }
            } catch (DriverLoadException ex) {
                LOGGER.debug("Unable to load database driver", ex);
                throw new DatabaseException("Unable to load database driver", ex);
            }
            userName = settings.getString(Settings.KEYS.DB_USER, "dcuser");
            //yes, yes - hard-coded password - only if there isn't one in the properties file.
            password = settings.getString(Settings.KEYS.DB_PASSWORD, "DC-Pass1337!");
            try {
                connectionString = settings.getConnectionString(
                        Settings.KEYS.DB_CONNECTION_STRING,
                        Settings.KEYS.DB_FILE_NAME);
            } catch (IOException ex) {
                LOGGER.debug("Unable to retrieve the database connection string", ex);
                throw new DatabaseException("Unable to retrieve the database connection string", ex);
            }

            boolean shouldCreateSchema = false;
            try {
                if (connectionString.startsWith("jdbc:h2:file:")) { //H2
                    shouldCreateSchema = !h2DataFileExists();
                    LOGGER.debug("Need to create DB Structure: {}", shouldCreateSchema);
                }
            } catch (IOException ioex) {
                LOGGER.debug("Unable to verify database exists", ioex);
                throw new DatabaseException("Unable to verify database exists", ioex);
            }
            LOGGER.debug("Loading database connection");
            LOGGER.debug("Connection String: {}", connectionString);
            LOGGER.debug("Database User: {}", userName);

            try {
                if (connectionString.toLowerCase().contains("integrated security=true")
                        || connectionString.toLowerCase().contains("trusted_connection=true")) {
                    conn = DriverManager.getConnection(connectionString);
                } else {
                    conn = DriverManager.getConnection(connectionString, userName, password);
                }
            } catch (SQLException ex) {
                if (ex.getMessage().contains("java.net.UnknownHostException") && connectionString.contains("AUTO_SERVER=TRUE;")) {
                    connectionString = connectionString.replace("AUTO_SERVER=TRUE;", "");
                    try {
                        conn = DriverManager.getConnection(connectionString, userName, password);
                        settings.setString(Settings.KEYS.DB_CONNECTION_STRING, connectionString);
                        LOGGER.debug("Unable to start the database in server mode; reverting to single user mode");
                    } catch (SQLException sqlex) {
                        LOGGER.debug("Unable to connect to the database", ex);
                        throw new DatabaseException("Unable to connect to the database", ex);
                    }
                } else {
                    LOGGER.debug("Unable to connect to the database", ex);
                    throw new DatabaseException("Unable to connect to the database", ex);
                }
            }
            if (shouldCreateSchema) {
                try {
                    createTables(conn);
                } catch (DatabaseException dex) {
                    LOGGER.debug("", dex);
                    throw new DatabaseException("Unable to create the database structure", dex);
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
     * Cleans up resources and unloads any registered database drivers. This
     * needs to be called to ensure the driver is unregistered prior to the
     * finalize method being called as during shutdown the class loader used to
     * load the driver may be unloaded prior to the driver being de-registered.
     */
    public synchronized void cleanup() {
        if (driver != null) {
            DriverLoader.cleanup(driver);
            driver = null;
        }
        connectionString = null;
        userName = null;
        password = null;
    }

    /**
     * Constructs a new database connection object per the database
     * configuration.
     *
     * @return a database connection object
     * @throws DatabaseException thrown if there is an exception loading the
     * database connection
     */
    public synchronized Connection getConnection() throws DatabaseException {
        initialize();
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(connectionString, userName, password);
        } catch (SQLException ex) {
            LOGGER.debug("", ex);
            throw new DatabaseException("Unable to connect to the database", ex);
        }
        return conn;
    }

    /**
     * Determines if the H2 database file exists. If it does not exist then the
     * data structure will need to be created.
     *
     * @return true if the H2 database file does not exist; otherwise false
     * @throws IOException thrown if the data directory does not exist and
     * cannot be created
     */
    public boolean h2DataFileExists() throws IOException {
        return h2DataFileExists(settings);
    }

    /**
     * Determines if the H2 database file exists. If it does not exist then the
     * data structure will need to be created.
     *
     * @param configuration the configured settings
     * @return true if the H2 database file does not exist; otherwise false
     * @throws IOException thrown if the data directory does not exist and
     * cannot be created
     */
    public static boolean h2DataFileExists(Settings configuration) throws IOException {
        final File file = getH2DataFile(configuration);
        return file.exists();
    }

    /**
     * Returns a reference to the H2 database file.
     *
     * @param configuration the configured settings
     * @return the path to the H2 database file
     * @throws IOException thrown if there is an error
     */
    public static File getH2DataFile(Settings configuration) throws IOException {
        final File dir = configuration.getH2DataDirectory();
        final String fileName = configuration.getString(Settings.KEYS.DB_FILE_NAME);
        final File file = new File(dir, fileName);
        return file;
    }

    /**
     * Determines if the connection string is for an H2 database.
     *
     * @return true if the connection string is for an H2 database
     */
    public boolean isH2Connection() {
        return isH2Connection(settings);
    }

    /**
     * Determines if the connection string is for an H2 database.
     *
     * @param configuration the configured settings
     * @return true if the connection string is for an H2 database
     */
    public static boolean isH2Connection(Settings configuration) {
        final String connStr;
        try {
            connStr = configuration.getConnectionString(
                    Settings.KEYS.DB_CONNECTION_STRING,
                    Settings.KEYS.DB_FILE_NAME);
        } catch (IOException ex) {
            LOGGER.debug("Unable to get connectionn string", ex);
            return false;
        }
        return connStr.startsWith("jdbc:h2:file:");
    }

    /**
     * Creates the database structure (tables and indexes) to store the CVE
     * data.
     *
     * @param conn the database connection
     * @throws DatabaseException thrown if there is a Database Exception
     */
    private void createTables(Connection conn) throws DatabaseException {
        LOGGER.debug("Creating database structure");

        try (InputStream is = FileUtils.getResourceAsStream(DB_STRUCTURE_RESOURCE)) {
            final String dbStructure = IOUtils.toString(is, StandardCharsets.UTF_8);

            Statement statement = null;
            try {
                statement = conn.createStatement();
                statement.execute(dbStructure);
            } catch (SQLException ex) {
                LOGGER.debug("", ex);
                throw new DatabaseException("Unable to create database statement", ex);
            } finally {
                DBUtils.closeStatement(statement);
            }
        } catch (IOException ex) {
            throw new DatabaseException("Unable to create database schema", ex);
        }
    }

    /**
     * Updates the database schema by loading the upgrade script for the version
     * specified. The intended use is that if the current schema version is 2.9
     * then we would call updateSchema(conn, "2.9"). This would load the
     * upgrade_2.9.sql file and execute it against the database. The upgrade
     * script must update the 'version' in the properties table.
     *
     * @param conn the database connection object
     * @param appExpectedVersion the schema version that the application expects
     * @param currentDbVersion the current schema version of the database
     * @throws DatabaseException thrown if there is an exception upgrading the
     * database schema
     */
    private void updateSchema(Connection conn, DependencyVersion appExpectedVersion, DependencyVersion currentDbVersion)
            throws DatabaseException {

        final String databaseProductName;
        try {
            databaseProductName = conn.getMetaData().getDatabaseProductName();
        } catch (SQLException ex) {
            throw new DatabaseException("Unable to get the database product name", ex);
        }
        if ("h2".equalsIgnoreCase(databaseProductName)) {
            LOGGER.debug("Updating database structure");
            final String updateFile = String.format(DB_STRUCTURE_UPDATE_RESOURCE, currentDbVersion.toString());
            try (InputStream is = FileUtils.getResourceAsStream(updateFile)) {
                if (is == null) {
                    throw new DatabaseException(String.format("Unable to load update file '%s'", updateFile));
                }
                final String dbStructureUpdate = IOUtils.toString(is, StandardCharsets.UTF_8);

                Statement statement = null;
                try {
                    statement = conn.createStatement();
                    final boolean success = statement.execute(dbStructureUpdate);
                    if (!success && statement.getUpdateCount() <= 0) {
                        throw new DatabaseException(String.format("Unable to upgrade the database schema to %s",
                                currentDbVersion.toString()));
                    }
                } catch (SQLException ex) {
                    LOGGER.debug("", ex);
                    throw new DatabaseException("Unable to update database schema", ex);
                } finally {
                    DBUtils.closeStatement(statement);
                }
            } catch (IOException ex) {
                final String msg = String.format("Upgrade SQL file does not exist: %s", updateFile);
                throw new DatabaseException(msg, ex);
            }
        } else {
            final int e0 = Integer.parseInt(appExpectedVersion.getVersionParts().get(0));
            final int c0 = Integer.parseInt(currentDbVersion.getVersionParts().get(0));
            final int e1 = Integer.parseInt(appExpectedVersion.getVersionParts().get(1));
            final int c1 = Integer.parseInt(currentDbVersion.getVersionParts().get(1));
            //CSOFF: EmptyBlock
            if (e0 == c0 && e1 < c1) {
                LOGGER.warn("A new version of dependency-check is available; consider upgrading");
                settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            } else if (e0 == c0 && e1 == c1) {
                //do nothing - not sure how we got here, but just in case...
            } else {
                LOGGER.error("The database schema must be upgraded to use this version of dependency-check. Please see {} for more information.",
                        UPGRADE_HELP_URL);
                throw new DatabaseException("Database schema is out of date");
            }
            //CSON: EmptyBlock
        }
    }

    /**
     * Uses the provided connection to check the specified schema version within
     * the database.
     *
     * @param conn the database connection object
     * @throws DatabaseException thrown if the schema version is not compatible
     * with this version of dependency-check
     */
    private void ensureSchemaVersion(Connection conn) throws DatabaseException {
        ResultSet rs = null;
        PreparedStatement ps = null;
        try {
            //TODO convert this to use DatabaseProperties
            ps = conn.prepareStatement("SELECT value FROM properties WHERE id = 'version'");
            rs = ps.executeQuery();
            if (rs.next()) {
                final String dbSchemaVersion = settings.getString(Settings.KEYS.DB_VERSION);
                final DependencyVersion appDbVersion = DependencyVersionUtil.parseVersion(dbSchemaVersion);
                if (appDbVersion == null) {
                    throw new DatabaseException("Invalid application database schema");
                }
                final DependencyVersion db = DependencyVersionUtil.parseVersion(rs.getString(1));
                if (db == null) {
                    throw new DatabaseException("Invalid database schema");
                }
                if (appDbVersion.compareTo(db) > 0) {
                    LOGGER.debug("Current Schema: {}", dbSchemaVersion);
                    LOGGER.debug("DB Schema: {}", rs.getString(1));
                    updateSchema(conn, appDbVersion, db);
                    if (++callDepth < 10) {
                        ensureSchemaVersion(conn);
                    }
                }
            } else {
                throw new DatabaseException("Database schema is missing");
            }
        } catch (SQLException ex) {
            LOGGER.debug("", ex);
            throw new DatabaseException("Unable to check the database schema version", ex);
        } finally {
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(ps);
        }
    }
}
