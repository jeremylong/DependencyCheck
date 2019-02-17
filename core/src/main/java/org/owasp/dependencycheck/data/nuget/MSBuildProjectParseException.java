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
 * Copyright (c) 2018 Paul Irwin. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nuget;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Exception during the parsing of a MSBuild Project file.
 *
 * @author paulirwin
 */
@ThreadSafe
public class MSBuildProjectParseException extends Exception {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 8190311907044058000L;

    /**
     * Constructs a new exception with <code>null</code> as its detail message.
     *
     * The cause is not initialized, and may subsequently be initialized by a
     * call to {@link java.lang.Throwable#initCause(java.lang.Throwable)}.
     */
    public MSBuildProjectParseException() {
        super();
    }

    /**
     * Constructs a new exception with the specified detail message. The cause
     * is not initialized, and may subsequently be initialized by a call to
     * {@link java.lang.Throwable#initCause(java.lang.Throwable)}.
     *
     * @param message the detail message. The detail message is saved for later
     * retrieval by the {@link java.lang.Throwable#getMessage()} method.
     */
    public MSBuildProjectParseException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * Note that the detail message associated with <code>cause</code> is
     * <em>not</em>
     * automatically incorporated in this exception's detail message.
     *
     * @param message the detail message (which is saved for later retrieval by
     * the {@link java.lang.Throwable#getMessage()} method.
     * @param cause the cause (which is saved for later retrieval by the
     * {@link java.lang.Throwable#getCause()} method). (A <code>null</code>
     * value is permitted, and indicates that the cause is nonexistent or
     * unknown).
     */
    public MSBuildProjectParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
