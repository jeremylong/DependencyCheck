/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.analyzer;

import org.codesecure.dependencycheck.analyzer.AbstractAnalyzer;
import java.util.Set;
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
public class AbstractAnalyzerTest {
    
    public AbstractAnalyzerTest() {
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
     * Test of newHashSet method, of class AbstractAnalyzer.
     */
    @Test
    public void testNewHashSet() {
        System.out.println("newHashSet");
        Set result = AbstractAnalyzer.newHashSet("one","two");
        assertEquals(2, result.size());
        assertTrue(result.contains("one"));
        assertTrue(result.contains("two"));
    }
}
