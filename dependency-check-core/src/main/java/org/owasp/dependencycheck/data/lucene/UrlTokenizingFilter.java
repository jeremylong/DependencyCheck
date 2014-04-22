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
 * <p>
 * Takes a TokenStream and splits or adds tokens to correctly index version numbers.</p>
 * <p>
 * <b>Example:</b> "3.0.0.RELEASE" -> "3 3.0 3.0.0 RELEASE 3.0.0.RELEASE".</p>
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class UrlTokenizingFilter extends AbstractTokenizingFilter {
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(UrlTokenizingFilter.class.getName());
    /**
     * Constructs a new VersionTokenizingFilter.
     *
     * @param stream the TokenStream that this filter will process
     */
    public UrlTokenizingFilter(TokenStream stream) {
        super(stream);
    }

    /**
     * Increments the underlying TokenStream and sets CharTermAttributes to construct an expanded set of tokens by
     * concatenating tokens with the previous token.
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
                            LOGGER.log(Level.FINE, "error parsing " + part, ex);
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
