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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.lucene;

import java.io.Reader;
import org.apache.lucene.analysis.util.CharTokenizer;
import org.apache.lucene.util.Version;

/**
 * Tokenizes the input breaking it into tokens when non-alpha/numeric characters
 * are found.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class AlphaNumericTokenizer extends CharTokenizer {

    /**
     * Constructs a new AlphaNumericTokenizer.
     *
     * @param matchVersion the lucene version
     * @param in the Reader
     */
    public AlphaNumericTokenizer(Version matchVersion, Reader in) {
        super(matchVersion, in);
    }

    /**
     * Constructs a new AlphaNumericTokenizer.
     *
     * @param matchVersion the lucene version
     * @param factory the AttributeFactory
     * @param in the Reader
     */
    public AlphaNumericTokenizer(Version matchVersion, AttributeFactory factory, Reader in) {
        super(matchVersion, factory, in);
    }

    /**
     * Determines if the char passed in is part of a token.
     *
     * @param c the char being analyzed
     * @return true if the char is a letter or digit, otherwise false
     */
    @Override
    protected boolean isTokenChar(int c) {
        return Character.isLetter(c) || Character.isDigit(c);
    }
}
