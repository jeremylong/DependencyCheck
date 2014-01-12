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
package org.owasp.dependencycheck.utils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class DBUtils {

    /**
     * Private constructor for a utility class.
     */
    private DBUtils() {
    }

    /**
     * Returns the generated integer primary key for a newly inserted row.
     *
     * @param statement a prepared statement that just executed an insert
     * @return a primary key
     * @throws DatabaseException thrown if there is an exception obtaining the
     * key
     */
    public static int getGeneratedKey(PreparedStatement statement) throws DatabaseException {
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
    public static void closeStatement(Statement statement) {
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
    public static void closeResultSet(ResultSet rs) {
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
