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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

/**
 * An exception used to indicate the db4o database is corrupt. This could be due
 * to invalid data or a complete failure of the db.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
class CorruptDatabaseException extends DatabaseException {

    /**
     * the serial version uid.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Creates an CorruptDatabaseException
     *
     * @param msg the exception message
     */
    public CorruptDatabaseException(String msg) {
        super(msg);
    }

    /**
     * Creates an CorruptDatabaseException
     *
     * @param msg the exception message
     * @param ex the cause of the exception
     */
    public CorruptDatabaseException(String msg, Exception ex) {
        super(msg, ex);
    }
}
