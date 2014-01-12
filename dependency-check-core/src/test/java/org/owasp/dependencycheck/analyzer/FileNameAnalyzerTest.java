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

import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.FileNameAnalyzer;
import java.io.File;
import java.util.Set;
import org.owasp.dependencycheck.dependency.Dependency;
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
        File struts = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        Dependency resultStruts = new Dependency(struts);
        File axis = new File(this.getClass().getClassLoader().getResource("axis2-adb-1.4.1.jar").getPath());
        Dependency resultAxis = new Dependency(axis);
        FileNameAnalyzer instance = new FileNameAnalyzer();
        instance.analyze(resultStruts, null);
        assertTrue(resultStruts.getVendorEvidence().toString().toLowerCase().contains("struts"));

        instance.analyze(resultAxis, null);
        assertTrue(resultStruts.getVersionEvidence().toString().toLowerCase().contains("2.1.2"));

    }

    /**
     * Test of initialize method, of class FileNameAnalyzer.
     */
    @Test
    public void testInitialize() throws Exception {
        FileNameAnalyzer instance = new FileNameAnalyzer();
        instance.initialize();
        assertTrue(true); //initialize does nothing.
    }

    /**
     * Test of close method, of class FileNameAnalyzer.
     */
    @Test
    public void testClose() throws Exception {
        FileNameAnalyzer instance = new FileNameAnalyzer();
        instance.close();
        assertTrue(true); //close does nothing.
    }
}
