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
package org.owasp.dependencycheck.data.nvdcve;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception thrown if an operation against the database fails.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class DatabaseException extends RuntimeException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = -2099842966372554285L;

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
