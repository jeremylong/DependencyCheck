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

import java.io.Reader;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.core.LowerCaseFilter;
import org.apache.lucene.analysis.core.StopAnalyzer;
import org.apache.lucene.analysis.core.StopFilter;
import org.apache.lucene.analysis.miscellaneous.WordDelimiterFilter;
import org.apache.lucene.util.Version;

/**
 * <p>
 * A Lucene Analyzer that utilizes the WhitespaceTokenizer, WordDelimiterFilter, LowerCaseFilter, and StopFilter. The
 * intended purpose of this Analyzer is to index the CPE fields vendor and product.</p>
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class FieldAnalyzer extends Analyzer {

    /**
     * The Lucene Version used.
     */
    private final Version version;

    /**
     * Creates a new FieldAnalyzer.
     *
     * @param version the Lucene version
     */
    public FieldAnalyzer(Version version) {
        this.version = version;
    }

    /**
     * Creates the TokenStreamComponents
     *
     * @param fieldName the field name being analyzed
     * @param reader the reader containing the input
     * @return the TokenStreamComponents
     */
    @Override
    protected TokenStreamComponents createComponents(String fieldName, Reader reader) {
        final Tokenizer source = new AlphaNumericTokenizer(version, reader);

        TokenStream stream = source;

        stream = new WordDelimiterFilter(stream,
                WordDelimiterFilter.CATENATE_WORDS
                | WordDelimiterFilter.GENERATE_WORD_PARTS
                | WordDelimiterFilter.GENERATE_NUMBER_PARTS
                | WordDelimiterFilter.PRESERVE_ORIGINAL
                | WordDelimiterFilter.SPLIT_ON_CASE_CHANGE
                | WordDelimiterFilter.SPLIT_ON_NUMERICS
                | WordDelimiterFilter.STEM_ENGLISH_POSSESSIVE, null);

        stream = new LowerCaseFilter(version, stream);
        stream = new StopFilter(version, stream, StopAnalyzer.ENGLISH_STOP_WORDS_SET);

        return new TokenStreamComponents(source, stream);
    }
}
