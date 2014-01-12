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
import org.apache.lucene.analysis.core.WhitespaceTokenizer;
import org.apache.lucene.util.Version;

/**
 * SearchVersionAnalyzer is a Lucene Analyzer used to analyze version
 * information.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 * @deprecated version information is no longer stored in lucene
 */
@Deprecated
public class SearchVersionAnalyzer extends Analyzer {
    //TODO consider implementing payloads/custom attributes...
    // use custom attributes for major, minor, x, x, x, rcx
    // these can then be used to weight the score for searches on the version.
    // see http://lucene.apache.org/core/3_6_1/api/core/org/apache/lucene/analysis/package-summary.html#package_description
    // look at this article to implement
    // http://www.codewrecks.com/blog/index.php/2012/08/25/index-your-blog-using-tags-and-lucene-net/

    /**
     * The Lucene Version used.
     */
    private final Version version;

    /**
     * Creates a new SearchVersionAnalyzer.
     *
     * @param version the Lucene version
     */
    public SearchVersionAnalyzer(Version version) {
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
        final Tokenizer source = new WhitespaceTokenizer(version, reader);
        TokenStream stream = source;
        stream = new LowerCaseFilter(version, stream);
        stream = new VersionTokenizingFilter(stream);
        return new TokenStreamComponents(source, stream);
    }
}
