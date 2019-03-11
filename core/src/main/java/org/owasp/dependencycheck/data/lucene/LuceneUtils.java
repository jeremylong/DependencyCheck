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
package org.owasp.dependencycheck.data.lucene;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import javax.annotation.concurrent.ThreadSafe;

/**
 * <p>
 * Lucene utils is a set of utilize written to make constructing Lucene queries
 * simpler.</p>
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class LuceneUtils {

    /**
     * Private constructor as this is a utility class.
     */
    private LuceneUtils() {
    }

    /**
     * Determines if the given term is a Lucene keyword (e.g. AND, OR, NOT).
     *
     * @param term the term to test
     * @return <code>true</code>if the term is a keyword; otherwise
     * <code>false</code>
     */
    public static boolean isKeyword(String term) {
        switch (term.toUpperCase()) {
            case "AND":
            case "OR":
            case "NOT":
            //the following are likely not needed, but may cause a rare issue so we'll consider them keywords
            case "TO":
            case "-":
            case "+":
                return true;
            default:
                return false;
        }
    }

    /**
     * Appends the text to the supplied StringBuilder escaping Lucene control
     * characters in the process.
     *
     * @param buf a StringBuilder to append the escaped text to
     * @param text the data to be escaped
     */
    @SuppressWarnings("fallthrough")
    @SuppressFBWarnings(justification = "As this is an encoding method the fallthrough is intentional", value = {"SF_SWITCH_NO_DEFAULT"})
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
                case '/':
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
        final int size = text.length() << 1;
        final StringBuilder buf = new StringBuilder(size);
        appendEscapedLuceneQuery(buf, text);
        return buf.toString();
    }
}
