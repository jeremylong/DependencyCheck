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
package org.codesecure.dependencycheck.data.lucene;

import java.io.IOException;
import java.util.LinkedList;
import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

/**
 * <p>Takes a TokenStream and splits or adds tokens to correctly index version numbers.</p>
 * <p><b>Example:</b> "3.0.0.RELEASE" -> "3 3.0 3.0.0 RELEASE 3.0.0.RELEASE".</p>
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public final class VersionTokenizingFilter extends TokenFilter {

    private final CharTermAttribute termAtt = addAttribute(CharTermAttribute.class);
    /**
     * A collection of tokens to add to the stream.
     */
    protected LinkedList<String> tokens = null;

    /**
     * Consructs a new VersionTokenizingFilter
     * @param stream the TokenStream that this filter will process
     */
    public VersionTokenizingFilter(TokenStream stream) {
        super(stream);
        tokens = new LinkedList<String>();
    }

    /**
     * Increments the underlying TokenStream and sets CharTermAtttributes to
     * construct an expanded set of tokens by concatenting tokens with the
     * previous token.
     *
     * @return whether or not we have hit the end of the TokenStream
     * @throws IOException is thrown when an IOException occurs
     */
    @Override
    public boolean incrementToken() throws IOException {
        if (tokens.size() == 0 && input.incrementToken()) {
            String version = new String(termAtt.buffer(), 0, termAtt.length());
            analyzeVersion(version);
        }
        return addTerm();
    }

    /**
     * Adds a term, if one exists, from the tokens collection..
     * @return
     */
    private boolean addTerm() {
        boolean termAdded = tokens.size() > 0;
        if (termAdded) {
            String version = tokens.pop();
            clearAttributes();
            termAtt.append(version);
        }
        return termAdded;
    }

    //major.minor[.maintenance[.build]]
    private void analyzeVersion(String version) {
        //todo should we also be splitting on dash or underscore? we would need
        //  to incorporate the dash or underscore back in...
        String[] versionParts = version.split("\\.");
        String dottedVersion = null;
        for (int x = 0; x < versionParts.length; x++) {
            String current = versionParts[x];
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
