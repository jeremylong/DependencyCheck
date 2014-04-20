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
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(DBUtils.class.getName());
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
     * @throws DatabaseException thrown if there is an exception obtaining the key
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
                LOGGER.log(Level.FINEST, statement.toString(), ex);
            }
        }
    }

    /**
     * Closes the result set capturing and ignoring any SQLExceptions that occur.
     *
     * @param rs a ResultSet to close
     */
    public static void closeResultSet(ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException ex) {
                LOGGER.log(Level.FINEST, rs.toString(), ex);
            }
        }
    }
}
