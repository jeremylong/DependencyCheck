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
import static org.apache.lucene.analysis.BaseTokenStreamTestCase.assertTokenStreamContents;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.core.WhitespaceTokenizer;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class TokenPairConcatenatingFilterTest extends BaseTokenStreamTestCase {

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

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

    /**
     * Test of clear method, of class TokenPairConcatenatingFilter.
     */
    @Test
    public void testClear() throws IOException {

        TokenStream ts = new WhitespaceTokenizer(LuceneUtils.CURRENT_VERSION, new StringReader("one two three"));
        TokenPairConcatenatingFilter filter = new TokenPairConcatenatingFilter(ts);
        assertTokenStreamContents(filter, new String[]{"one", "onetwo", "two", "twothree", "three"});

        assertNotNull(filter.getPreviousWord());
        filter.clear();
        assertNull(filter.getPreviousWord());
        assertTrue(filter.getWords().isEmpty());
    }
}
