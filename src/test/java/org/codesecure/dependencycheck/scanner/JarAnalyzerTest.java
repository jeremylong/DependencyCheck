/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.scanner;

import java.util.HashSet;
import java.io.File;
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
public class JarAnalyzerTest {
    
    public JarAnalyzerTest() {
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
     * Test of insepct method, of class JarAnalyzer.
     * @throws Exception is thrown when an excpetion occurs.
     */
    @Test
    public void testInsepct() throws Exception {
        System.out.println("insepct");
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        JarAnalyzer instance = new JarAnalyzer();
        Dependency result = instance.insepct(file);
        assertEquals("C30B57142E1CCBC1EFD5CD15F307358F", result.getMd5sum());
        assertEquals("89CE9E36AA9A9E03F1450936D2F4F8DD0F961F8B", result.getSha1sum());
        assertTrue(result.getVendorEvidence().toString().toLowerCase().contains("apache"));
        assertTrue(result.getVendorEvidence().getWeighting().contains("apache"));
    }

    /**
     * Test of getSupportedExtensions method, of class JarAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        System.out.println("getSupportedExtensions");
        JarAnalyzer instance = new JarAnalyzer();
        Set expResult = new HashSet();
        expResult.add("jar");
        Set result = instance.getSupportedExtensions();
        assertEquals(expResult, result);
    }

    /**
     * Test of getName method, of class JarAnalyzer.
     */
    @Test
    public void testGetName() {
        System.out.println("getName");
        JarAnalyzer instance = new JarAnalyzer();
        String expResult = "Jar Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of supportsExtension method, of class JarAnalyzer.
     */
    @Test
    public void testSupportsExtension() {
        System.out.println("supportsExtension");
        String extension = "jar";
        JarAnalyzer instance = new JarAnalyzer();
        boolean expResult = true;
        boolean result = instance.supportsExtension(extension);
        assertEquals(expResult, result);
    }
}
