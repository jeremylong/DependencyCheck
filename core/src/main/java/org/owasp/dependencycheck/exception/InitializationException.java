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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.exception;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception used when initializing analyzers.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class InitializationException extends Exception {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 6034529098584358957L;

    /**
     * Whether or not the exception is fatal.
     */
    private boolean fatal = true;

    /**
     * Get the value of fatal.
     *
     * @return the value of fatal
     */
    public boolean isFatal() {
        return fatal;
    }

    /**
     * Set the value of fatal.
     *
     * @param fatal new value of fatal
     */
    public void setFatal(boolean fatal) {
        this.fatal = fatal;
    }

    /**
     * Creates a new InitializationException.
     */
    public InitializationException() {
        super();
    }

    /**
     * Creates a new InitializationException.
     *
     * @param msg a message for the exception.
     */
    public InitializationException(String msg) {
        super(msg);
    }

    /**
     * Creates a new InitializationException.
     *
     * @param ex the cause of the exception.
     */
    public InitializationException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new InitializationException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the exception.
     */
    public InitializationException(String msg, Throwable ex) {
        super(msg, ex);
    }

    /**
     * Creates a new InitializationException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the exception.
     * @param fatal whether or not the exception is fatal.
     */
    public InitializationException(String msg, Throwable ex, boolean fatal) {
        super(msg, ex);
        this.fatal = fatal;
    }
}
