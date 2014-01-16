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
import org.apache.lucene.analysis.core.WhitespaceTokenizer;
import org.apache.lucene.util.Version;

/**
 * VersionAnalyzer is a Lucene Analyzer used to analyze version information.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 * @deprecated version information is no longer stored in lucene
 */
@Deprecated
public class VersionAnalyzer extends Analyzer {
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
     * Creates a new VersionAnalyzer.
     *
     * @param version the Lucene version
     */
    public VersionAnalyzer(Version version) {
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
        return new TokenStreamComponents(source, stream);
    }
}
