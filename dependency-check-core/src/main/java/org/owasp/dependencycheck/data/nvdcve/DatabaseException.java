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
 * An exception thrown if an operation against the database fails.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DatabaseException extends Exception {

    /**
     * the serial version uid.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Creates an DatabaseException.
     *
     * @param msg the exception message
     */
    public DatabaseException(String msg) {
        super(msg);
    }

    /**
     * Creates an DatabaseException.
     *
     * @param ex the cause of the exception
     */
    public DatabaseException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates an DatabaseException.
     *
     * @param msg the exception message
     * @param ex the cause of the exception
     */
    public DatabaseException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
