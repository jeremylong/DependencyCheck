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
 * <p>A Lucene Analyzer that utilizes the WhitespaceTokenizer,
 * WordDelimiterFilter, LowerCaseFilter, and StopFilter. The intended purpose of
 * this Analyzer is to index the CPE fields vendor and product.</p>
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
