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
package org.owasp.dependencycheck.exception;

import java.io.IOException;

/**
 * An exception used when the data needed does not exist to perform analysis.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NoDataException extends IOException {

    /**
     * The serial version uid.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new NoDataException.
     */
    public NoDataException() {
        super();
    }

    /**
     * Creates a new NoDataException.
     *
     * @param msg a message for the exception.
     */
    public NoDataException(String msg) {
        super(msg);
    }

    /**
     * Creates a new NoDataException.
     *
     * @param ex the cause of the exception.
     */
    public NoDataException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new NoDataException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the exception.
     */
    public NoDataException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
