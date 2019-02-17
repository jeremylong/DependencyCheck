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
 * An exception used to indicate the db4o database is corrupt. This could be due
 * to invalid data or a complete failure of the db.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class CorruptDatabaseException extends DatabaseException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = -5651552077861934103L;

    /**
     * Creates an CorruptDatabaseException.
     *
     * @param msg the exception message
     */
    public CorruptDatabaseException(String msg) {
        super(msg);
    }

    /**
     * Creates an CorruptDatabaseException.
     *
     * @param msg the exception message
     * @param ex the cause of the exception
     */
    public CorruptDatabaseException(String msg, Exception ex) {
        super(msg, ex);
    }
}
