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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.exception;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An InvalidDataDataException is a generic exception used when trying to load
 * the NVD CVE meta data.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class InvalidDataException extends Exception {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 2511103356591299027L;

    /**
     * Creates an InvalidDataException.
     *
     * @param msg the exception message
     */
    public InvalidDataException(String msg) {
        super(msg);
    }

    /**
     * Creates an InvalidDataException.
     *
     * @param msg the exception message
     * @param ex the cause of the exception
     */
    public InvalidDataException(String msg, Exception ex) {
        super(msg, ex);
    }
}
