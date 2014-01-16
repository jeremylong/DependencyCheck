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

import java.io.IOException;
import java.util.LinkedList;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

/**
 * <p>
 * Takes a TokenStream and splits or adds tokens to correctly index version numbers.</p>
 * <p>
 * <b>Example:</b> "3.0.0.RELEASE" -> "3 3.0 3.0.0 RELEASE 3.0.0.RELEASE".</p>
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 * @deprecated version information is no longer stored in lucene
 */
@Deprecated
public final class VersionTokenizingFilter extends AbstractTokenizingFilter {

    /**
     * Constructs a new VersionTokenizingFilter.
     *
     * @param stream the TokenStream that this filter will process
     */
    public VersionTokenizingFilter(TokenStream stream) {
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
            final String version = new String(termAtt.buffer(), 0, termAtt.length());
            final String[] toAnalyze = version.split("[_-]");
            //ensure we analyze the whole string as one too
            analyzeVersion(version);
            for (String str : toAnalyze) {
                analyzeVersion(str);
            }
        }
        return addTerm();
    }

    /**
     * <p>
     * Analyzes the version and adds several copies of the version as different tokens. For example, the version 1.2.7
     * would create the tokens 1 1.2 1.2.7. This is useful in discovering the correct version - sometimes a maintenance
     * or build number will throw off the version identification.</p>
     *
     * <p>
     * expected&nbsp;format:&nbps;major.minor[.maintenance[.build]]</p>
     *
     * @param version the version to analyze
     */
    private void analyzeVersion(String version) {
        //todo should we also be splitting on dash or underscore? we would need
        //  to incorporate the dash or underscore back in...
        final LinkedList<String> tokens = getTokens();
        final String[] versionParts = version.split("\\.");
        String dottedVersion = null;
        for (String current : versionParts) {
            if (!current.matches("^/d+$")) {
                tokens.add(current);
            }
            if (dottedVersion == null) {
                dottedVersion = current;
            } else {
                dottedVersion = dottedVersion + "." + current;
            }
            tokens.add(dottedVersion);
        }
    }
}
