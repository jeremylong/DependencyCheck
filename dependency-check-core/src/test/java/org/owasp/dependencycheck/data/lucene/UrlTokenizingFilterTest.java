/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.data.lucene;

import java.io.IOException;
import java.io.Reader;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.Analyzer.TokenStreamComponents;
import org.apache.lucene.analysis.BaseTokenStreamTestCase;
import static org.apache.lucene.analysis.BaseTokenStreamTestCase.checkOneTerm;
import org.apache.lucene.analysis.MockTokenizer;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.core.KeywordTokenizer;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class UrlTokenizingFilterTest extends BaseTokenStreamTestCase {

    private Analyzer analyzer;

    public UrlTokenizingFilterTest() {
        analyzer = new Analyzer() {
            @Override
            protected TokenStreamComponents createComponents(String fieldName,
                    Reader reader) {
                Tokenizer source = new MockTokenizer(reader, MockTokenizer.WHITESPACE, false);
                return new TokenStreamComponents(source, new UrlTokenizingFilter(source));
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
     * test some example domains
     */
    public void testExamples() throws IOException {
        String[] expected = new String[2];
        expected[0] = "domain";
        expected[1] = "test";
        assertAnalyzesTo(analyzer, "http://www.domain.com/test.php", expected);
        checkOneTerm(analyzer, "https://apache.org", "apache");
    }

    /**
     * copied from
     * http://svn.apache.org/repos/asf/lucene/dev/trunk/lucene/analysis/common/src/test/org/apache/lucene/analysis/en/TestEnglishMinimalStemFilter.java
     * blast some random strings through the analyzer
     */
    public void testRandomStrings() throws Exception {
        checkRandomData(random(), analyzer, 1000 * RANDOM_MULTIPLIER);
    }

    /**
     * copied from
     * http://svn.apache.org/repos/asf/lucene/dev/trunk/lucene/analysis/common/src/test/org/apache/lucene/analysis/en/TestEnglishMinimalStemFilter.java
     *
     * @throws IOException
     */
    public void testEmptyTerm() throws IOException {
        Analyzer a = new Analyzer() {
            @Override
            protected TokenStreamComponents createComponents(String fieldName, Reader reader) {
                Tokenizer tokenizer = new KeywordTokenizer(reader);
                return new TokenStreamComponents(tokenizer, new UrlTokenizingFilter(tokenizer));
            }
        };
        checkOneTermReuse(a, "", "");
    }
}
