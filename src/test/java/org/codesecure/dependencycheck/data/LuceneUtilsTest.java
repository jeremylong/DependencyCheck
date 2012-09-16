/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class LuceneUtilsTest {
    
    public LuceneUtilsTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of appendEscapedLuceneQuery method, of class LuceneUtils.
     */
    @Test
    public void testAppendEscapedLuceneQuery() {
        System.out.println("appendEscapedLuceneQuery");
        StringBuilder buf = new StringBuilder();
        CharSequence text = "test encoding + - & | ! ( ) { } [ ] ^ \" ~ * ? : \\";
        String expResult = "test encoding \\+ \\- \\& \\| \\! \\( \\) \\{ \\} \\[ \\] \\^ \\\" \\~ \\* \\? \\: \\\\"; 
        LuceneUtils.appendEscapedLuceneQuery(buf, text);
        assertEquals(expResult, buf.toString());
    }
/**
     * Test of appendEscapedLuceneQuery method, of class LuceneUtils.
     */
    @Test
    public void testAppendEscapedLuceneQuery_null() {
        System.out.println("appendEscapedLuceneQuery");
        StringBuilder buf = new StringBuilder();
        CharSequence text = null;
        LuceneUtils.appendEscapedLuceneQuery(buf, text);
        assertEquals(0, buf.length());
    }
    /**
     * Test of escapeLuceneQuery method, of class LuceneUtils.
     */
    @Test
    public void testEscapeLuceneQuery() {
        System.out.println("escapeLuceneQuery");
        CharSequence text = "test encoding + - & | ! ( ) { } [ ] ^ \" ~ * ? : \\"; 
        String expResult = "test encoding \\+ \\- \\& \\| \\! \\( \\) \\{ \\} \\[ \\] \\^ \\\" \\~ \\* \\? \\: \\\\"; 
        String result = LuceneUtils.escapeLuceneQuery(text);
        assertEquals(expResult, result);
    }
    
    /**
     * Test of escapeLuceneQuery method, of class LuceneUtils.
     */
    @Test
    public void testEscapeLuceneQuery_null() {
        System.out.println("escapeLuceneQuery");
        CharSequence text = null;
        String expResult = null;
        String result = LuceneUtils.escapeLuceneQuery(text);
        assertEquals(expResult, result);
    }
}
