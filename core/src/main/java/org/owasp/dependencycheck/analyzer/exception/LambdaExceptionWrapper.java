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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer.exception;

/**
 * An exception intended to be used within a lambda expression as checked
 * exceptions cannot be used within lambdas.
 *
 * @author Jeremy Long
 */
public class LambdaExceptionWrapper extends RuntimeException {

    /**
     * The serial version UID.
     */
    private static final long serialVersionUID = 367437431232631044L;

    /**
     * Wraps an exception.
     *
     * @param ex the exception to wrap
     */
    public LambdaExceptionWrapper(Exception ex) {
        super(ex);
    }
}
