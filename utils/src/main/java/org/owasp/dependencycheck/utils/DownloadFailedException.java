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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.IOException;

/**
 * An exception used when a download fails.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public class DownloadFailedException extends IOException {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 4937242754894484078L;

    /**
     * Creates a new DownloadFailedException.
     */
    public DownloadFailedException() {
        super();
    }

    /**
     * Creates a new DownloadFailedException.
     *
     * @param msg a message for the exception.
     */
    public DownloadFailedException(String msg) {
        super(msg);
    }

    /**
     * Creates a new DownloadFailedException.
     *
     * @param ex the cause of the download failure.
     */
    public DownloadFailedException(Throwable ex) {
        super(ex);
    }

    /**
     * Creates a new DownloadFailedException.
     *
     * @param msg a message for the exception.
     * @param ex the cause of the download failure.
     */
    public DownloadFailedException(String msg, Throwable ex) {
        super(msg, ex);
    }
}
