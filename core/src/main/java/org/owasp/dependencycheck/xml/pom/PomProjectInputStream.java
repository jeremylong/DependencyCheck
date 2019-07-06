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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.pom;

import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Filters everything in an input stream prior to the &lt;project&gt; element.
 * This is useful to filter out the DOCTYPE declarations that can cause parsing
 * issues.
 *
 * @author Jeremy Long
 */
public class PomProjectInputStream extends FilterInputStream {

    /**
     * The project tag for a pom.xml.
     */
    private static final byte[] PROJECT = {60, 112, 114, 111, 106, 101, 99, 116};
    //private static final byte[] PROJECT = "<project".getBytes();

    /**
     * The size of the buffer used to scan the input stream.
     */
    protected static final int BUFFER_SIZE = 1024;

    /**
     * Constructs a new POM project filtering input stream. The input stream is
     * wrapped in a buffered input stream.
     *
     * @param in the input stream
     * @throws IOException thrown if there is an I/O error
     */
    public PomProjectInputStream(InputStream in) throws IOException {
        super(new BufferedInputStream(in));
        skipToProject();
    }

    /**
     * Skips bytes from the input stream until it finds the &lt;project&gt;
     * element.
     *
     * @throws IOException thrown if an I/O error occurs
     */
    private void skipToProject() throws IOException {
        final byte[] buffer = new byte[BUFFER_SIZE];
        super.mark(BUFFER_SIZE);
        int count = super.read(buffer, 0, BUFFER_SIZE);
        while (count > 0) {
            final int pos = findSequence(PROJECT, buffer);
            if (pos >= 0) {
                super.reset();
                final long skipped = super.skip((long) pos);
                if (skipped != pos) {
                    throw new IOException("Error skipping pom header information");
                }
                return;
            } else if (count - PROJECT.length == 0) {
                return;
            }
            super.reset();
            final long skipTo = (long) count - PROJECT.length;
            final long skipped = super.skip(skipTo);
            if (skipped != skipTo) {
                throw new IOException("Error skipping pom header information");
            }
            super.mark(BUFFER_SIZE);
            count = super.read(buffer, 0, BUFFER_SIZE);
        }
    }

    /**
     * Tests the buffer to see if it contains the given sequence[1]..[n]. It is
     * assumed that sequence[0] is checked prior to calling this method and that
     * buffer[pos] equals sequence[0].
     *
     * @param sequence the prefix to scan against
     * @param buffer the buffer to scan
     * @param pos the position in the buffer to being searching
     * @return <code>true</code>if the next set of bytes from the input stream
     * match the contents of the prefix.
     */
    private static boolean testRemaining(byte[] sequence, byte[] buffer, int pos) {
        boolean match = true;
        for (int i = 1; i < sequence.length; i++) {
            if (buffer[pos + i] != sequence[i]) {
                match = false;
                break;
            }
        }
        return match;
    }

    /**
     * Finds the start of the given sequence in the buffer. If not found, -1 is
     * returned.
     *
     * @param sequence the sequence to locate
     * @param buffer the buffer to search
     * @return the starting position of the sequence in the buffer if found;
     * otherwise -1
     */
    protected static int findSequence(byte[] sequence, byte[] buffer) {
        int pos = -1;
        for (int i = 0; i < buffer.length - sequence.length + 1; i++) {
            if (buffer[i] == sequence[0] && testRemaining(sequence, buffer, i)) {
                pos = i;
                break;
            }
        }
        return pos;
    }
}
