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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class FileNameAnalyzerTest {

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
