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
package org.owasp.dependencycheck.utils;

import java.io.IOException;

/**
 * An exception used when a download fails.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DownloadFailedException extends IOException {

    /**
     * The serial version UID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new DownloadFailedException.
     */
    public DownloadFailedException() {
        super();
    }

    /**
     * Creates a new DownloadFailedException.
     *
     * @param msg a message for the exception.
     */
    public DownloadFailedException(String msg) {
        super(msg);
    }

    /**
     * Creates a new DownloadFailedException.
     *
     * @param ex the cause of the download failure.
     */
    public DownloadFailedException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new DownloadFailedException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the download failure.
     */
    public DownloadFailedException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
