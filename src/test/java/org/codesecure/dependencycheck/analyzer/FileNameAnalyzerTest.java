/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.analyzer;

import java.io.File;
import java.util.Set;
import org.codesecure.dependencycheck.dependency.Dependency;
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
public class FileNameAnalyzerTest {

    public FileNameAnalyzerTest() {
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
     * Test of getSupportedExtensions method, of class FileNameAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        System.out.println("getSupportedExtensions");
        FileNameAnalyzer instance = new FileNameAnalyzer();
        Set expResult = null;
        Set result = instance.getSupportedExtensions();
        assertEquals(expResult, result);
    }

    /**
     * Test of getName method, of class FileNameAnalyzer.
     */
    @Test
    public void testGetName() {
        System.out.println("getName");
        FileNameAnalyzer instance = new FileNameAnalyzer();
        String expResult = "File Name Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of supportsExtension method, of class FileNameAnalyzer.
     */
    @Test
    public void testSupportsExtension() {
        System.out.println("supportsExtension");
        String extension = "any";
        FileNameAnalyzer instance = new FileNameAnalyzer();
        boolean expResult = true;
        boolean result = instance.supportsExtension(extension);
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class FileNameAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        System.out.println("getAnalysisPhase");
        FileNameAnalyzer instance = new FileNameAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyze method, of class FileNameAnalyzer.
     */
    @Test
    public void testAnalyze() throws Exception {
        System.out.println("analyze");
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        Dependency result = new Dependency(file);
        FileNameAnalyzer instance = new FileNameAnalyzer();
        instance.analyze(result, null);
        assertTrue(result.getVendorEvidence().toString().toLowerCase().contains("struts"));
    }

    /**
     * Test of initialize method, of class FileNameAnalyzer.
     */
    @Test
    public void testInitialize() {
        System.out.println("initialize");
        FileNameAnalyzer instance = new FileNameAnalyzer();
        instance.initialize();
        assertTrue(true); //initialize does nothing.
    }

    /**
     * Test of close method, of class FileNameAnalyzer.
     */
    @Test
    public void testClose() {
        System.out.println("close");
        FileNameAnalyzer instance = new FileNameAnalyzer();
        instance.close();
        assertTrue(true); //close does nothing.
    }
}
