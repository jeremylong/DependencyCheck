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

import java.io.IOException;
import java.util.LinkedList;
import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

/**
 * <p>Takes a TokenStream and adds additional tokens by concatenating pairs of
 * words.</p>
 * <p><b>Example:</b> "Spring Framework Core" -> "Spring SpringFramework
 * Framework FrameworkCore Core".</p>
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class TokenPairConcatenatingFilter extends TokenFilter {

    /**
     * The char term attribute.
     */
    private final CharTermAttribute termAtt = addAttribute(CharTermAttribute.class);
    /**
     * The previous word parsed.
     */
    private String previousWord;
    /**
     * A list of words parsed.
     */
    private final LinkedList<String> words;

    /**
     * Returns the previous word. This is needed in the test cases.
     *
     * @return te previous word
     */
    protected String getPreviousWord() {
        return previousWord;
    }

    /**
     * Returns the words list. This is needed in the test cases.
     *
     * @return the words list
     */
    protected LinkedList<String> getWords() {
        return words;
    }

    /**
     * Constructs a new TokenPairConcatenatingFilter.
     *
     * @param stream the TokenStream that this filter will process
     */
    public TokenPairConcatenatingFilter(TokenStream stream) {
        super(stream);
        words = new LinkedList<String>();
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

        //collect all the terms into the words collection
        while (input.incrementToken()) {
            final String word = new String(termAtt.buffer(), 0, termAtt.length());
            words.add(word);
        }

        //if we have a previousTerm - write it out as its own token concatenated
        // with the current word (if one is available).
        if (previousWord != null && words.size() > 0) {
            final String word = words.getFirst();
            clearAttributes();
            termAtt.append(previousWord).append(word);
            previousWord = null;
            return true;
        }
        //if we have words, write it out as a single token
        if (words.size() > 0) {
            final String word = words.removeFirst();
            clearAttributes();
            termAtt.append(word);
            previousWord = word;
            return true;
        }
        return false;
    }

    /**
     * <p>Resets the Filter and clears any internal state data that may have
     * been left-over from previous uses of the Filter.</p>
     * <p><b>If this Filter is re-used this method must be called between
     * uses.</b></p>
     */
    public void clear() {
        previousWord = null;
        words.clear();
    }
}
