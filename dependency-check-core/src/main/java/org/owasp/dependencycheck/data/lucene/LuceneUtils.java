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
package org.owasp.dependencycheck.data.lucene;

import org.apache.lucene.util.Version;

/**
 * <p>Lucene utils is a set of utilize written to make constructing Lucene
 * queries simpler.</p>
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class LuceneUtils {

    /**
     * The current version of Lucene being used. Declaring this one place so an
     * upgrade doesn't require hunting through the code base.
     */
    public static final Version CURRENT_VERSION = Version.LUCENE_45;

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
    @edu.umd.cs.findbugs.annotations.SuppressWarnings(
            value = "SF_SWITCH_NO_DEFAULT",
            justification = "The switch below does have a default.")
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
