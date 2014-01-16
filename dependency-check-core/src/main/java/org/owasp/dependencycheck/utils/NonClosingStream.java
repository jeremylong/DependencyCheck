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
package org.owasp.dependencycheck.utils;

import java.io.FilterInputStream;
import java.io.InputStream;

/**
 * NonClosingStream is a stream filter which prevents another class that processes the stream from closing it. This is
 * necessary when dealing with things like JAXB and zipInputStreams.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NonClosingStream extends FilterInputStream {

    /**
     * Constructs a new NonClosingStream.
     *
     * @param in an input stream.
     */
    public NonClosingStream(InputStream in) {
        super(in);
    }

    /**
     * Prevents closing of the stream.
     */
    @Override
    public void close() {
        // don't close the stream.
    }
}
