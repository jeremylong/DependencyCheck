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

import java.util.LinkedList;
import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

/**
 * An abstract tokenizing filter that can be used as the base for a tokenizing
 * filter.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public abstract class AbstractTokenizingFilter extends TokenFilter {

    /**
     * The char term attribute.
     */
    private final CharTermAttribute termAtt = addAttribute(CharTermAttribute.class);

    /**
     * Gets the CharTermAttribute.
     *
     * @return the CharTermAttribute
     */
    protected CharTermAttribute getTermAtt() {
        return termAtt;
    }
    /**
     * A collection of tokens to add to the stream.
     */
    private final LinkedList<String> tokens;

    /**
     * Gets the list of tokens.
     *
     * @return the list of tokens
     */
    protected LinkedList<String> getTokens() {
        return tokens;
    }

    /**
     * Constructs a new AbstractTokenizingFilter.
     *
     * @param stream the TokenStream that this filter will process
     */
    public AbstractTokenizingFilter(TokenStream stream) {
        super(stream);
        tokens = new LinkedList<String>();
    }

    /**
     * Adds a term, if one exists, from the tokens collection.
     *
     * @return whether or not a new term was added
     */
    protected boolean addTerm() {
        final boolean termAdded = tokens.size() > 0;
        if (termAdded) {
            final String term = tokens.pop();
            clearAttributes();
            termAtt.append(term);
        }
        return termAdded;
    }
}
