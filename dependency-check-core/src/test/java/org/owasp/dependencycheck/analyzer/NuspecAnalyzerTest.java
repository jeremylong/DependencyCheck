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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;

import java.io.File;

public class NuspecAnalyzerTest extends BaseTest {

    private NuspecAnalyzer instance;

    @Before
    public void setUp() throws Exception {
        instance = new NuspecAnalyzer();
        instance.initialize();
        instance.setEnabled(true);
    }

    @Test
    public void testGetAnalyzerName() {
        assertEquals("Nuspec Analyzer", instance.getName());
    }

    @Test
    public void testSupportsFileExtensions() {
        assertTrue(instance.accept(new File("test.nuspec")));
        assertFalse(instance.accept(new File("test.nupkg")));
    }

    @Test
    public void testGetAnalysisPhaze() {
        assertEquals(AnalysisPhase.INFORMATION_COLLECTION, instance.getAnalysisPhase());
    }
    
    @Test
    public void testNuspecAnalysis() throws Exception {
    	 
        File file = BaseTest.getResourceAsFile(this, "nuspec/test.nuspec");
        Dependency result = new Dependency(file);
        instance.analyze(result, null);
        
        assertEquals(NuspecAnalyzer.DEPENDENCY_ECOSYSTEM,result.getEcosystem());
        
        //checking the owner field
        assertTrue(result.getVendorEvidence().toString().toLowerCase().contains("bobsmack"));
        
        //checking the author field
        assertTrue(result.getVendorEvidence().toString().toLowerCase().contains("brianfox"));
        
        //checking the id field
        assertTrue(result.getProductEvidence().toString().contains("TestDepCheck"));
        
        //checking the title field
        assertTrue(result.getProductEvidence().toString().contains("Test Package"));
        
        assertTrue(result.getVersionEvidence().toString().contains("1.0.0"));
        assertEquals("1.0.0", result.getVersion());
        assertEquals("TestDepCheck", result.getName());
        assertEquals("TestDepCheck:1.0.0", result.getDisplayFileName());        
    }    
}

// vim: cc=120:sw=4:ts=4:sts=4
