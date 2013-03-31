/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.lucene;

/**
 * <p>Lucene utils is a set of utilize written to make constructing Lucene
 * queries simpler.</p>
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public final class LuceneUtils {

    /**
     * Private constructor as this is a utility class.
     */
    private LuceneUtils() {
    }

    /**
     * Appends the text to the supplied StringBuilder escaping Lucene control
     * characters in the process.
     *
     * @param buf a StringBuilder to append the escaped text to
     * @param text the data to be escaped
     */
    @SuppressWarnings("fallthrough")
    public static void appendEscapedLuceneQuery(StringBuilder buf,
            final CharSequence text) {

        if (text == null || buf == null) {
            return;
        }

        for (int i = 0; i < text.length(); i++) {
            final char c = text.charAt(i);
            switch (c) {
                case '+':
                case '-':
                case '&':
                case '|':
                case '!':
                case '(':
                case ')':
                case '{':
                case '}':
                case '[':
                case ']':
                case '^':
                case '"':
                case '~':
                case '*':
                case '?':
                case ':':
                case '\\': //it is supposed to fall through here
                    buf.append('\\');
                default:
                    buf.append(c);
                    break;
            }
        }
    }

    /**
     * Escapes the text passed in so that it is treated as data instead of
     * control characters.
     *
     * @param text data to be escaped
     * @return the escaped text.
     */
    public static String escapeLuceneQuery(final CharSequence text) {

        if (text == null) {
            return null;
        }

        int size = text.length();
        size = size >> 1;
        final StringBuilder buf = new StringBuilder(size);

        appendEscapedLuceneQuery(buf, text);

        return buf.toString();
    }
}
