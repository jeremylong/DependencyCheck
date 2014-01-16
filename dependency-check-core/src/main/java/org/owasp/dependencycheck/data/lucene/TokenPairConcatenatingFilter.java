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
import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

/**
 * <p>
 * Takes a TokenStream and adds additional tokens by concatenating pairs of words.</p>
 * <p>
 * <b>Example:</b> "Spring Framework Core" -> "Spring SpringFramework Framework FrameworkCore Core".</p>
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
     * Increments the underlying TokenStream and sets CharTermAttributes to construct an expanded set of tokens by
     * concatenating tokens with the previous token.
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
     * <p>
     * Resets the Filter and clears any internal state data that may have been left-over from previous uses of the
     * Filter.</p>
     * <p>
     * <b>If this Filter is re-used this method must be called between uses.</b></p>
     */
    public void clear() {
        previousWord = null;
        words.clear();
    }
}
