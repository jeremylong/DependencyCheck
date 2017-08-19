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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.lucene;

import java.io.IOException;
import java.io.StringReader;
import org.apache.lucene.analysis.BaseTokenStreamTestCase;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.core.WhitespaceTokenizer;
import org.junit.After;

import org.junit.Before;

/**
 *
 * @author Jeremy Long
 */
public class TokenPairConcatenatingFilterTest extends BaseTokenStreamTestCase {

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * test some examples
     */
    public void testExamples() throws IOException {
        Tokenizer wsTokenizer = new WhitespaceTokenizer(LuceneUtils.CURRENT_VERSION, new StringReader("one two three"));
        TokenStream filter = new TokenPairConcatenatingFilter(wsTokenizer);
        assertTokenStreamContents(filter,
                new String[]{"one", "onetwo", "two", "twothree", "three"});
    }
}
