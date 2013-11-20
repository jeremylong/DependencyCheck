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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import static org.owasp.dependencycheck.data.nvdcve.CveDB.DB_SCHEMA_VERSION;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class BaseDB {

    /**
     * Resource location for SQL file used to create the database schema.
     */
    public static final String DB_STRUCTURE_RESOURCE = "data/initialize.sql";
    /**
     * The version of the current DB Schema.
     */
    public static final String DB_SCHEMA_VERSION = "2.7";
    /**
     * Database connection
     */
    private Connection conn;

    /**
     * Returns the database connection.
     *
     * @return the database connection
     */
    protected Connection getConnection() {
        return conn;
    }

    /**
     * Opens the database connection. If the database does not exist, it will
     * create a new one.
     *
     * @throws IOException thrown if there is an IO Exception
     * @throws SQLException thrown if there is a SQL Exception
     * @throws DatabaseException thrown if there is an error initializing a new
     * database
     * @throws ClassNotFoundException thrown if the h2 database driver cannot be
     * loaded
     */
    @edu.umd.cs.findbugs.annotations.SuppressWarnings(
            value = "DMI_EMPTY_DB_PASSWORD",
            justification = "Yes, I know... Blank password.")
    public void open() throws IOException, SQLException, DatabaseException, ClassNotFoundException {
        final String fileName = CveDB.getDataDirectory().getCanonicalPath();
        final File f = new File(fileName, "cve." + DB_SCHEMA_VERSION);
        final File check = new File(f.getAbsolutePath() + ".h2.db");
        final boolean createTables = !check.exists();
        final String connStr = String.format("jdbc:h2:file:%s;AUTO_SERVER=TRUE", f.getAbsolutePath());
        Class.forName("org.h2.Driver");
        conn = DriverManager.getConnection(connStr, "sa", "");
        if (createTables) {
            createTables();
        }
    }

    /**
     * Closes the DB4O database. Close should be called on this object when it
     * is done being used.
     */
    public void close() {
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException ex) {
                final String msg = "There was an error attempting to close the CveDB, see the log for more details.";
                Logger.getLogger(BaseDB.class.getName()).log(Level.SEVERE, msg, ex);
                Logger.getLogger(BaseDB.class.getName()).log(Level.FINE, null, ex);
            }
            conn = null;
        }
    }

    /**
     * Commits all completed transactions.
     *
     * @throws SQLException thrown if a SQL Exception occurs
     */
    public void commit() throws SQLException {
        if (conn != null) {
            conn.commit();
        }
    }

    /**
     * Cleans up the object and ensures that "close" has been called.
     *
     * @throws Throwable thrown if there is a problem
     */
    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize(); //not necessary if extending Object.
    }

    /**
     * Creates the database structure (tables and indexes) to store the CVE data
     *
     * @throws SQLException thrown if there is a sql exception
     * @throws DatabaseException thrown if there is a database exception
     */
    private void createTables() throws SQLException, DatabaseException {
        InputStream is;
        InputStreamReader reader;
        BufferedReader in = null;
        try {
            is = this.getClass().getClassLoader().getResourceAsStream(DB_STRUCTURE_RESOURCE);
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
            } finally {
                closeStatement(statement);
            }
        } catch (IOException ex) {
            throw new DatabaseException("Unable to create database schema", ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    Logger.getLogger(CveDB.class
                            .getName()).log(Level.FINEST, null, ex);
                }
            }
        }
    }

    /**
     * Retrieves the directory that the JAR file exists in so that we can ensure
     * we always use a common data directory.
     *
     * @return the data directory for this index.
     * @throws IOException is thrown if an IOException occurs of course...
     */
    public static File getDataDirectory() throws IOException {
        final File path = Settings.getFile(Settings.KEYS.CVE_DATA_DIRECTORY);
        if (!path.exists()) {
            if (!path.mkdirs()) {
                throw new IOException("Unable to create NVD CVE Data directory");
            }
        }
        return path;
    }

    /**
     * Returns the generated integer primary key for a newly inserted row.
     *
     * @param statement a prepared statement that just executed an insert
     * @return a primary key
     * @throws DatabaseException thrown if there is an exception obtaining the
     * key
     */
    protected int getGeneratedKey(PreparedStatement statement) throws DatabaseException {
        ResultSet rs = null;
        int id = 0;
        try {
            rs = statement.getGeneratedKeys();
            rs.next();
            id = rs.getInt(1);
        } catch (SQLException ex) {
            throw new DatabaseException("Unable to get primary key for inserted row");
        } finally {
            closeResultSet(rs);
        }
        return id;
    }

    /**
     * Closes the given statement object ignoring any exceptions that occur.
     *
     * @param statement a Statement object
     */
    public void closeStatement(Statement statement) {
        if (statement != null) {
            try {
                statement.close();
            } catch (SQLException ex) {
                Logger.getLogger(CveDB.class
                        .getName()).log(Level.FINEST, statement.toString(), ex);
            }
        }
    }

    /**
     * Closes the result set capturing and ignoring any SQLExceptions that
     * occur.
     *
     * @param rs a ResultSet to close
     */
    public void closeResultSet(ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException ex) {
                Logger.getLogger(CveDB.class
                        .getName()).log(Level.FINEST, rs.toString(), ex);
            }
        }
    }
}
