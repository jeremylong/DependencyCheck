/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.Properties;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
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
 * @author Jeremy Long <jeremy.long@owasp.org>
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
     * Test of inspect method, of class JarAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testAnalyze() throws Exception {
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        Dependency result = new Dependency(file);
        JarAnalyzer instance = new JarAnalyzer();
        instance.analyze(result, null);
        assertTrue(result.getVendorEvidence().toString().toLowerCase().contains("apache"));
        assertTrue(result.getVendorEvidence().getWeighting().contains("apache"));

        file = new File(this.getClass().getClassLoader().getResource("org.mortbay.jetty.jar").getPath());
        result = new Dependency(file);
        instance.analyze(result, null);
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
        instance.analyze(result, null);
        assertEquals("org.mortbar,jmx.jar has version evidence?", result.getVersionEvidence().size(), 0);
    }

    /**
     * Test of getSupportedExtensions method, of class JarAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        JarAnalyzer instance = new JarAnalyzer();
        Set expResult = new HashSet();
        expResult.add("jar");
        expResult.add("war");
        Set result = instance.getSupportedExtensions();
        assertEquals(expResult, result);
    }

    /**
     * Test of getName method, of class JarAnalyzer.
     */
    @Test
    public void testGetName() {
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
