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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.HashSet;
import java.util.Set;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class JavaScriptAnalyzerTest {

    public JavaScriptAnalyzerTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getSupportedExtensions method, of class JavaScriptAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        JavaScriptAnalyzer instance = new JavaScriptAnalyzer();
        Set expResult = new HashSet<String>();
        expResult.add("js");
        Set result = instance.getSupportedExtensions();
        assertEquals(expResult, result);
    }

    /**
     * Test of getName method, of class JavaScriptAnalyzer.
     */
    @Test
    public void testGetName() {
        System.out.println("getName");
        JavaScriptAnalyzer instance = new JavaScriptAnalyzer();
        String expResult = "JavaScript Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of supportsExtension method, of class JavaScriptAnalyzer.
     */
    @Test
    public void testSupportsExtension() {
        String extension = "js";
        JavaScriptAnalyzer instance = new JavaScriptAnalyzer();
        boolean expResult = true;
        boolean result = instance.supportsExtension(extension);
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class JavaScriptAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        JavaScriptAnalyzer instance = new JavaScriptAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyze method, of class JavaScriptAnalyzer.
     */
    @Test
    public void testAnalyze() throws Exception {
        File jq6 = new File(this.getClass().getClassLoader().getResource("jquery-1.6.2.min.js").getPath());
        File jq10 = new File(this.getClass().getClassLoader().getResource("jquery-1.10.2.js").getPath());
        File jq10min = new File(this.getClass().getClassLoader().getResource("jquery-1.10.2.min.js").getPath());
        Dependency depJQ6 = new Dependency(jq6);
        Dependency depJQ10 = new Dependency(jq10);
        Dependency depJQ10min = new Dependency(jq10min);
        Engine engine = null;
        JavaScriptAnalyzer instance = new JavaScriptAnalyzer();

//        assertTrue(depJQ6.getEvidence().size() == 0);
//        assertTrue(depJQ10.getEvidence().size() == 0);
//        assertTrue(depJQ10min.getEvidence().size() == 0);
//
//        instance.analyze(depJQ6, engine);
//        instance.analyze(depJQ10, engine);
//        instance.analyze(depJQ10min, engine);
//        //TODO improve the assertions
//        assertTrue(depJQ6.getEvidence().size() > 0);
//        assertTrue(depJQ10.getEvidence().size() > 0);
//        assertTrue(depJQ10min.getEvidence().size() > 0);
    }

    /**
     * Test of initialize method, of class JavaScriptAnalyzer.
     */
    @Test
    public void testInitialize() throws Exception {
    }

    /**
     * Test of close method, of class JavaScriptAnalyzer.
     */
    @Test
    public void testClose() throws Exception {

    }
}
