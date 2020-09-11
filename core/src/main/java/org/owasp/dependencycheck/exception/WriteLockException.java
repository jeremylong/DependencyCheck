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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.exception;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception used when trying to obtain a lock on a resource.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class WriteLockException extends Exception {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 8987298706527142594L;

    /**
     * Creates a new WriteLockException.
     */
    public WriteLockException() {
        super();
    }

    /**
     * Creates a new WriteLockException.
     *
     * @param msg a message for the exception.
     */
    public WriteLockException(String msg) {
        super(msg);
    }

    /**
     * Creates a new WriteLockException.
     *
     * @param ex the cause of the exception.
     */
    public WriteLockException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new WriteLockException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the exception.
     */
    public WriteLockException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
