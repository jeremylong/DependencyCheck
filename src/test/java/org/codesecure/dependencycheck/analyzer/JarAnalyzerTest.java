/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.analyzer;

import java.util.Properties;
import org.codesecure.dependencycheck.analyzer.JarAnalyzer;
import org.codesecure.dependencycheck.dependency.Dependency;
import org.codesecure.dependencycheck.dependency.Evidence;
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
    public void testAnalyze() throws Exception {
        System.out.println("analyze");
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        Dependency result = new Dependency(file);
        JarAnalyzer instance = new JarAnalyzer();
        instance.analyze(result);
        assertTrue(result.getVendorEvidence().toString().toLowerCase().contains("apache"));
        assertTrue(result.getVendorEvidence().getWeighting().contains("apache"));


        file = new File(this.getClass().getClassLoader().getResource("org.mortbay.jetty.jar").getPath());
        result = new Dependency(file);
        instance.analyze(result);
        boolean found = false;
        for (Evidence e : result.getProductEvidence()) {
            if (e.getName().equalsIgnoreCase("package-title")
                    && e.getValue().equalsIgnoreCase("org.mortbay.http")) {
                found = true;
                break;
            }
        }
        assertTrue("package-title of org.mortbay.http not found in org.mortbay.jetty.jar", found);

        found = false;
        for (Evidence e : result.getVendorEvidence()) {
            if (e.getName().equalsIgnoreCase("implementation-url")
                    && e.getValue().equalsIgnoreCase("http://jetty.mortbay.org")) {
                found = true;
                break;
            }
        }
        assertTrue("implementation-url of http://jetty.mortbay.org not found in org.mortbay.jetty.jar", found);

        found = false;
        for (Evidence e : result.getVersionEvidence()) {
            if (e.getName().equalsIgnoreCase("Implementation-Version")
                    && e.getValue().equalsIgnoreCase("4.2.27")) {
                found = true;
                break;
            }
        }
        assertTrue("implementation-version of 4.2.27 not found in org.mortbay.jetty.jar", found);

        file = new File(this.getClass().getClassLoader().getResource("org.mortbay.jmx.jar").getPath());
        result = new Dependency(file);
        instance.analyze(result);
        assertEquals("org.mortbar,jmx.jar has version evidence?", result.getVersionEvidence().size(), 0);
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
    
    @Test
    public void testInterpolateString() {
        Properties prop = new Properties();
        prop.setProperty("key", "value");
        prop.setProperty("nested", "nested ${key}");
        String text = "This is a test of '${key}' '${nested}'";
        String expResults = "This is a test of 'value' 'nested value'";
        JarAnalyzer instance = new JarAnalyzer();
        String results = instance.interpolateString(text, prop);
        assertEquals(expResults, results);
    }
}
