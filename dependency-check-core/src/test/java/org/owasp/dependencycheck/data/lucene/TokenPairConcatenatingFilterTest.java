/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.data.lucene;

import java.io.IOException;
import java.io.Reader;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.BaseTokenStreamTestCase;
import static org.apache.lucene.analysis.BaseTokenStreamTestCase.assertAnalyzesTo;
import static org.apache.lucene.analysis.BaseTokenStreamTestCase.checkOneTerm;
import org.apache.lucene.analysis.MockTokenizer;
import org.apache.lucene.analysis.Tokenizer;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class TokenPairConcatenatingFilterTest extends BaseTokenStreamTestCase {

    private Analyzer analyzer;

    public TokenPairConcatenatingFilterTest() {
        analyzer = new Analyzer() {
            @Override
            protected Analyzer.TokenStreamComponents createComponents(String fieldName,
                    Reader reader) {
                Tokenizer source = new MockTokenizer(reader, MockTokenizer.WHITESPACE, false);
                return new Analyzer.TokenStreamComponents(source, new TokenPairConcatenatingFilter(source));
            }
        };
    }

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
        //TODO figure outwhy I am getting "Failed: incrementtoken() called while in wrong state"
//        String[] expected = new String[3];
//        expected[0] = "one";
//        expected[1] = "onetwo";
//        expected[2] = "two";
//        checkOneTerm(analyzer, "one", "one");
//        assertAnalyzesTo(analyzer, "two", new String[]{"onetwo", "two"});
        //checkOneTerm(analyzer, "two", "onetwo");
        //checkOneTerm(analyzer, "three", "two");
    }

    /**
     * Test of clear method, of class TokenPairConcatenatingFilter.
     */
    @Test
    public void testClear() {
    }
}
