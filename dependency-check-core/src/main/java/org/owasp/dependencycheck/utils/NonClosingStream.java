/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.FilterInputStream;
import java.io.InputStream;

/**
 * NonClosingStream is a stream filter which prevents another class that
 * processes the stream from closing it. This is necessary when dealing with
 * things like JAXB and zipInputStreams.
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
