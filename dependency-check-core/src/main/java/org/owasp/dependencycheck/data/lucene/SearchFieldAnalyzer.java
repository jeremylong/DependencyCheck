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
 * A Lucene field analyzer used to analyzer queries against the CPE data.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class SearchFieldAnalyzer extends Analyzer {

    /**
     * The Lucene Version used.
     */
    private final Version version;
    /**
     * A local reference to the TokenPairConcatenatingFilter so that we can
     * clear any left over state if this analyzer is re-used.
     */
    private TokenPairConcatenatingFilter concatenatingFilter;

    /**
     * Constructs a new SearchFieldAnalyzer.
     *
     * @param version the Lucene version
     */
    public SearchFieldAnalyzer(Version version) {
        this.version = version;
    }

    /**
     * Creates a the TokenStreamComponents used to analyze the stream.
     *
     * @param fieldName the field that this lucene analyzer will process
     * @param reader a reader containing the tokens
     * @return the token stream filter chain
     */
    @Override
    protected TokenStreamComponents createComponents(String fieldName, Reader reader) {
        final Tokenizer source = new AlphaNumericTokenizer(version, reader);

        TokenStream stream = source;

        stream = new WordDelimiterFilter(stream,
                WordDelimiterFilter.GENERATE_WORD_PARTS
                | WordDelimiterFilter.GENERATE_NUMBER_PARTS
                | WordDelimiterFilter.PRESERVE_ORIGINAL
                | WordDelimiterFilter.SPLIT_ON_CASE_CHANGE
                | WordDelimiterFilter.SPLIT_ON_NUMERICS
                | WordDelimiterFilter.STEM_ENGLISH_POSSESSIVE, null);

        stream = new LowerCaseFilter(version, stream);
        stream = new UrlTokenizingFilter(stream);
        concatenatingFilter = new TokenPairConcatenatingFilter(stream);
        stream = concatenatingFilter;
        stream = new StopFilter(version, stream, StopAnalyzer.ENGLISH_STOP_WORDS_SET);

        return new TokenStreamComponents(source, stream);
    }

    /**
     * <p>Resets the analyzer and clears any internal state data that may have
     * been left-over from previous uses of the analyzer.</p>
     * <p><b>If this analyzer is re-used this method must be called between
     * uses.</b></p>
     */
    public void clear() {
        if (concatenatingFilter != null) {
            concatenatingFilter.clear();
        }
    }
}
