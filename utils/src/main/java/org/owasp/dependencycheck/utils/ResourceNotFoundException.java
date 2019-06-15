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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception used when the resource could not be retrieved because a 404 was
 * received.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class ResourceNotFoundException extends Exception {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 4205588006979138520L;

    /**
     * Creates a new ResourceNotFoundException.
     */
    public ResourceNotFoundException() {
        super();
    }

    /**
     * Creates a new ResourceNotFoundException.
     *
     * @param msg a message for the exception.
     */
    public ResourceNotFoundException(String msg) {
        super(msg);
    }

    /**
     * Creates a new ResourceNotFoundException.
     *
     * @param ex the cause of the exception.
     */
    public ResourceNotFoundException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new ResourceNotFoundException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the exception.
     */
    public ResourceNotFoundException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
