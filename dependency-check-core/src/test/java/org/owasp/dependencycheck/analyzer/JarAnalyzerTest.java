/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;

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
