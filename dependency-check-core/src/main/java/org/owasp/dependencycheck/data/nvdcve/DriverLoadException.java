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

/**
 * An exception thrown the database driver is unable to be loaded.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DriverLoadException extends Exception {

    /**
     * the serial version uid.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Creates an DriverLoadException.
     *
     * @param msg the exception message
     */
    public DriverLoadException(String msg) {
        super(msg);
    }

    /**
     * Creates an DriverLoadException.
     *
     * @param ex the cause of the exception
     */
    public DriverLoadException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates an DriverLoadException.
     *
     * @param msg the exception message
     * @param ex the cause of the exception
     */
    public DriverLoadException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
