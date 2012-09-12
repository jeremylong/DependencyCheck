/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.scanner;

import java.util.Set;
import java.util.Iterator;
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
public class AnalyzerServiceTest {
    
    public AnalyzerServiceTest() {
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
     * Test of getAnalyzers method, of class AnalyzerService.
     */
    @Test
    public void testGetAnalyzers() {
        System.out.println("getAnalyzers");
        AnalyzerService instance = AnalyzerService.getInstance();
        Iterator<Analyzer> result = instance.getAnalyzers();

        boolean found = false;
        while (result.hasNext()) {
            Analyzer a = result.next();
            Set<String> e = a.getSupportedExtensions();
            if (e.contains("jar")) {
                found = true;
            }
        }
        assertTrue("JarAnalyzer loaded", found);
    }
}
