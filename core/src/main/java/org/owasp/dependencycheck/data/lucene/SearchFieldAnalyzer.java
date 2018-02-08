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

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.core.LowerCaseFilter;
import org.apache.lucene.analysis.core.StopAnalyzer;
import org.apache.lucene.analysis.core.StopFilter;
import org.apache.lucene.analysis.core.WhitespaceTokenizer;
import org.apache.lucene.analysis.miscellaneous.WordDelimiterFilter;
import org.apache.lucene.analysis.util.CharArraySet;

/**
 * A Lucene field analyzer used to analyzer queries against the CPE data.
 *
 * @author Jeremy Long
 */
public class SearchFieldAnalyzer extends Analyzer {

    /**
     * The list of additional stop words to use.
     */
    private static final String[] ADDITIONAL_STOP_WORDS = {"software", "framework", "inc",
        "com", "org", "net", "www", "consulting", "ltd", "foundation", "project"};
    /**
     * The set of stop words to use in the analyzer.
     */
    private final CharArraySet stopWords;

    /**
     * Returns the set of stop words being used.
     *
     * @return the set of stop words being used
     */
    public static CharArraySet getStopWords() {
        final CharArraySet words = StopFilter.makeStopSet(ADDITIONAL_STOP_WORDS, true);
        words.addAll(StopAnalyzer.ENGLISH_STOP_WORDS_SET);
        return words;
    }

    /**
     * Constructs a new SearchFieldAnalyzer.
     *
     */
    public SearchFieldAnalyzer() {
        stopWords = getStopWords();
    }

    /**
     * Creates a the TokenStreamComponents used to analyze the stream.
     *
     * @param fieldName the field that this lucene analyzer will process
     * @return the token stream filter chain
     */
    @Override
    protected TokenStreamComponents createComponents(String fieldName) {
        //final Tokenizer source = new AlphaNumericTokenizer();
        final Tokenizer source = new WhitespaceTokenizer();
        TokenStream stream = source;

        stream = new UrlTokenizingFilter(stream);
        stream = new AlphaNumericFilter(stream);
        stream = new WordDelimiterFilter(stream,
                WordDelimiterFilter.GENERATE_WORD_PARTS
                | WordDelimiterFilter.GENERATE_NUMBER_PARTS
                | WordDelimiterFilter.PRESERVE_ORIGINAL
                | WordDelimiterFilter.SPLIT_ON_CASE_CHANGE
                | WordDelimiterFilter.SPLIT_ON_NUMERICS
                | WordDelimiterFilter.STEM_ENGLISH_POSSESSIVE, null);

        stream = new LowerCaseFilter(stream);

        stream = new StopFilter(stream, stopWords);
        stream = new TokenPairConcatenatingFilter(stream);

        return new TokenStreamComponents(source, stream);
    }
}
