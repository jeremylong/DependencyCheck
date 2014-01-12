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
package org.owasp.dependencycheck.data.update.exception;

import java.io.IOException;

/**
 * An exception used when an error occurs reading a setting.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class UpdateException extends IOException {

    /**
     * The serial version uid.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new UpdateException.
     */
    public UpdateException() {
        super();
    }

    /**
     * Creates a new UpdateException.
     *
     * @param msg a message for the exception.
     */
    public UpdateException(String msg) {
        super(msg);
    }

    /**
     * Creates a new UpdateException.
     *
     * @param ex the cause of the update exception.
     */
    public UpdateException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new UpdateException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the update exception.
     */
    public UpdateException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
