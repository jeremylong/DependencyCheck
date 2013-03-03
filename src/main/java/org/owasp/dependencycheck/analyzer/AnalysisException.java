/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

/**
 * An exception thrown when the analysis of a dependency fails.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class AnalysisException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a new AnalysisException.
     */
    public AnalysisException() {
        super();
    }

    /**
     * Creates a new AnalysisException.
     *
     * @param msg a message for the exception.
     */
    public AnalysisException(String msg) {
        super(msg);
    }

    /**
     * Creates a new AnalysisException.
     *
     * @param ex the cause of the failure.
     */
    public AnalysisException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new DownloadFailedException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the failure.
     */
    public AnalysisException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
