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
package org.owasp.dependencycheck.analyzer.exception;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception thrown when files in an archive cannot be extracted.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class ArchiveExtractionException extends Exception {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 5654160114034311518L;

    /**
     * Creates a new ArchiveExtractionException.
     */
    public ArchiveExtractionException() {
        super();
    }

    /**
     * Creates a new ArchiveExtractionException.
     *
     * @param msg a message for the exception.
     */
    public ArchiveExtractionException(String msg) {
        super(msg);
    }

    /**
     * Creates a new ArchiveExtractionException.
     *
     * @param ex the cause of the failure.
     */
    public ArchiveExtractionException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new ArchiveExtractionException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the failure.
     */
    public ArchiveExtractionException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
