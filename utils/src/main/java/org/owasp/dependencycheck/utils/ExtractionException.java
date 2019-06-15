/*
 * This file is part of dependency-check-utils.
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

import java.io.IOException;

/**
 * An exception used when a file is unable to be un-zipped.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public class ExtractionException extends IOException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = -7257246289191278761L;

    /**
     * Creates a new ExtractionException.
     */
    public ExtractionException() {
        super();
    }

    /**
     * Creates a new ExtractionException.
     *
     * @param msg a message for the exception.
     */
    public ExtractionException(String msg) {
        super(msg);
    }

    /**
     * Creates a new ExtractionException.
     *
     * @param ex the cause of the download failure.
     */
    public ExtractionException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new ExtractionException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the download failure.
     */
    public ExtractionException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
