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
package org.owasp.dependencycheck.exception;

import java.io.IOException;
import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception used when the data needed does not exist to perform analysis.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class NoDataException extends IOException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 2048042874653986535L;

    /**
     * Creates a new NoDataException.
     */
    public NoDataException() {
        super();
    }

    /**
     * Creates a new NoDataException.
     *
     * @param msg a message for the exception.
     */
    public NoDataException(String msg) {
        super(msg);
    }

    /**
     * Creates a new NoDataException.
     *
     * @param ex the cause of the exception.
     */
    public NoDataException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new NoDataException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the exception.
     */
    public NoDataException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
