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

import java.io.IOException;
import java.util.LinkedList;
import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

/**
 * <p>Takes a TokenStream and splits or adds tokens to correctly index version
 * numbers.</p>
 * <p><b>Example:</b> "3.0.0.RELEASE" -> "3 3.0 3.0.0 RELEASE
 * 3.0.0.RELEASE".</p>
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public final class VersionTokenizingFilter extends TokenFilter {

    /**
     * The char term attribute.
     */
    private final CharTermAttribute termAtt = addAttribute(CharTermAttribute.class);
    /**
     * A collection of tokens to add to the stream.
     */
    private LinkedList<String> tokens;

    /**
     * Constructs a new VersionTokenizingFilter.
     *
     * @param stream the TokenStream that this filter will process
     */
    public VersionTokenizingFilter(TokenStream stream) {
        super(stream);
        tokens = new LinkedList<String>();
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
     * Adds a term, if one exists, from the tokens collection.
     *
     * @return whether or not a new term was added
     */
    private boolean addTerm() {
        final boolean termAdded = tokens.size() > 0;
        if (termAdded) {
            final String version = tokens.pop();
            clearAttributes();
            termAtt.append(version);
        }
        return termAdded;
    }

    /**
     * <p>Analyzes the version and adds several copies of the version as
     * different tokens. For example, the version 1.2.7 would create the tokens
     * 1 1.2 1.2.7. This is useful in discovering the correct version -
     * sometimes a maintenance or build number will throw off the version
     * identification.</p>
     *
     * <p>expected&nbsp;format:&nbps;major.minor[.maintenance[.build]]</p>
     *
     * @param version the version to analyze
     */
    private void analyzeVersion(String version) {
        //todo should we also be splitting on dash or underscore? we would need
        //  to incorporate the dash or underscore back in...
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
