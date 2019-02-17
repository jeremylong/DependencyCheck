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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.exception;

import java.io.IOException;
import javax.annotation.concurrent.ThreadSafe;

/**
 * An exception used when using @{link DependencyCheckScanAgent} to conduct a
 * scan and the scan fails.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class ScanAgentException extends IOException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 941993541958815367L;

    /**
     * Creates a new ScanAgentException.
     */
    public ScanAgentException() {
        super();
    }

    /**
     * Creates a new ScanAgentException.
     *
     * @param msg a message for the exception.
     */
    public ScanAgentException(String msg) {
        super(msg);
    }

    /**
     * Creates a new ScanAgentException.
     *
     * @param ex the cause of the exception.
     */
    public ScanAgentException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new ScanAgentException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the exception.
     */
    public ScanAgentException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
