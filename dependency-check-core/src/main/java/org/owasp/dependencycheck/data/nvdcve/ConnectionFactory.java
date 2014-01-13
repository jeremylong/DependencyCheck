/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
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
     * The version of the current DB Schema.
     */
    public static final String DB_SCHEMA_VERSION = "2.8";
    /**
     * Resource location for SQL file used to create the database schema.
     */
    public static final String DB_STRUCTURE_RESOURCE = "data/initialize.sql";

    /**
     * Private constructor for this factory class; no instance is ever needed.
     */
    private ConnectionFactory() {
    }

    /**
     * Constructs a new database connection object per the database configuration. This will load the appropriate
     * database driver, via the DriverManager, if configured.
     *
     * @return a database connection object
     * @throws DatabaseException thrown if there is an exception loading the database connection
     */
    public static Connection getConnection() throws DatabaseException {
        Connection conn = null;
        try {
            Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Loading database connection");

            final String connStr = getConnectionString();
            final String user = Settings.getString(Settings.KEYS.DB_USER, "dcuser");
            //yes, yes - hard-coded password - only if there isn't one in the properties file.
            final String pass = Settings.getString(Settings.KEYS.DB_PASSWORD, "DC-Pass1337!");
            Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Connection String: {0}", connStr);
            Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Database User: {0}", user);
            boolean createTables = false;
            if (connStr.startsWith("jdbc:h2:file:")) { //H2
                createTables = needToCreateDatabaseStructure();
                Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Need to create DB Structure: {0}", createTables);
            }
            final String driverName = Settings.getString(Settings.KEYS.DB_DRIVER_NAME, "");
            if (!driverName.isEmpty()) { //likely need to load the correct driver
                Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Loading driver: {0}", driverName);
                final String driverPath = Settings.getString(Settings.KEYS.DB_DRIVER_PATH, "");
                if (!driverPath.isEmpty()) { //ugh, driver is not on classpath?
                    Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Loading driver from: {0}", driverPath);
                    DriverLoader.load(driverName, driverPath);
                } else {
                    DriverLoader.load(driverName);
                }
            }

            //JDBC4 drivers don't need this call.
            //Class.forName("org.h2.Driver");
            conn = DriverManager.getConnection(connStr, user, pass);
            if (createTables) {
                createTables(conn);
            } else {
                ensureSchemaVersion(conn);
            }
        } catch (IOException ex) {
            Logger.getLogger(ConnectionFactory.class.getName()).log(Level.FINE, null, ex);
            throw new DatabaseException("Unable to load database");
        } catch (DriverLoadException ex) {
            Logger.getLogger(ConnectionFactory.class.getName()).log(Level.FINE, null, ex);
            throw new DatabaseException("Unable to load database driver");
        } catch (SQLException ex) {
            Logger.getLogger(ConnectionFactory.class.getName()).log(Level.FINE, null, ex);
            throw new DatabaseException("Unable to connect to the database");
        } catch (DatabaseException ex) {
            Logger.getLogger(ConnectionFactory.class.getName()).log(Level.FINE, null, ex);
            throw new DatabaseException("Unable to create the database structure");
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
            final String fileName = getDataDirectory().getCanonicalPath();
            final File file = new File(fileName, "cve." + DB_SCHEMA_VERSION);
            return String.format(connStr, file.getAbsolutePath());
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
    private static boolean needToCreateDatabaseStructure() throws IOException {
        final File dir = getDataDirectory();
        final String name = String.format("cve.%s.h2.db", DB_SCHEMA_VERSION);
        final File file = new File(dir, name);
        return !file.exists();
    }

    /**
     * Creates the database structure (tables and indexes) to store the CVE data.
     *
     * @param conn the database connection
     * @throws DatabaseException thrown if there is a Database Exception
     */
    private static void createTables(Connection conn) throws DatabaseException {
        Logger.getLogger(ConnectionFactory.class.getName()).log(Level.FINE, "Creating database structure");
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
                Logger.getLogger(ConnectionFactory.class.getName()).log(Level.FINE, null, ex);
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
                    Logger.getLogger(ConnectionFactory.class.getName()).log(Level.FINEST, null, ex);
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
            Logger.getLogger(ConnectionFactory.class.getName()).log(Level.FINE, null, ex);
            throw new DatabaseException("Unable to check the database schema version");
        } finally {
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(cs);
        }
    }
}
