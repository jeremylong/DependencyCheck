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
package org.owasp.dependencycheck.concurrency;

/**
 * If thrown, indicates that a problem occurred when locking a directory.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DirectoryLockException extends Exception {

    /**
     * Default serial version UID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new Directory Lock Exception.
     */
    public DirectoryLockException() {
        super();
    }

    /**
     * Constructs a new Directory Lock Exception.
     *
     * @param msg the message describing the exception
     */
    public DirectoryLockException(String msg) {
        super(msg);
    }

    /**
     * Constructs a new Directory Lock Exception.
     *
     * @param ex the cause of the exception
     */
    public DirectoryLockException(Throwable ex) {
        super(ex);
    }

    /**
     * Constructs a new Directory Lock Exception.
     *
     * @param msg the message describing the exception
     * @param ex the cause of the exception
     */
    public DirectoryLockException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
