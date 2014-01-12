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

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;
import org.owasp.dependencycheck.utils.UrlStringUtils;

/**
 * <p>Takes a TokenStream and splits or adds tokens to correctly index version
 * numbers.</p>
 * <p><b>Example:</b> "3.0.0.RELEASE" -> "3 3.0 3.0.0 RELEASE
 * 3.0.0.RELEASE".</p>
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class UrlTokenizingFilter extends AbstractTokenizingFilter {

    /**
     * Constructs a new VersionTokenizingFilter.
     *
     * @param stream the TokenStream that this filter will process
     */
    public UrlTokenizingFilter(TokenStream stream) {
        super(stream);
    }

    /**
     * Increments the underlying TokenStream and sets CharTermAttributes to
     * construct an expanded set of tokens by concatenating tokens with the
     * previous token.
     *
     * @return whether or not we have hit the end of the TokenStream
     * @throws IOException is thrown when an IOException occurs
     */
    @Override
    public boolean incrementToken() throws IOException {
        final LinkedList<String> tokens = getTokens();
        final CharTermAttribute termAtt = getTermAtt();
        if (tokens.size() == 0 && input.incrementToken()) {
            final String text = new String(termAtt.buffer(), 0, termAtt.length());
            if (UrlStringUtils.containsUrl(text)) {
                final String[] parts = text.split("\\s");
                for (String part : parts) {
                    if (UrlStringUtils.isUrl(part)) {
                        try {
                            final List<String> data = UrlStringUtils.extractImportantUrlData(part);
                            tokens.addAll(data);
                        } catch (MalformedURLException ex) {
                            Logger.getLogger(UrlTokenizingFilter.class.getName()).log(Level.INFO, "error parsing " + part, ex);
                            tokens.add(part);
                        }
                    } else {
                        tokens.add(part);
                    }
                }
            } else {
                tokens.add(text);
            }
        }
        return addTerm();
    }
}
