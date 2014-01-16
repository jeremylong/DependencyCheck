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
