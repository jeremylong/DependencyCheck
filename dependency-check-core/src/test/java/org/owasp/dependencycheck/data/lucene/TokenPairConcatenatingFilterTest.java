/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.data.lucene;

import java.io.IOException;
import java.io.StringReader;
import org.apache.lucene.analysis.BaseTokenStreamTestCase;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.core.WhitespaceTokenizer;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.apache.lucene.analysis.BaseTokenStreamTestCase.assertTokenStreamContents;
import static org.junit.Assert.*;

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
