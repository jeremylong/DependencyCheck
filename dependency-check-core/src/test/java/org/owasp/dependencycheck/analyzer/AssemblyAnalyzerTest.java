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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;

/**
 * Tests for the AssemblyAnalyzer.
 * @author colezlaw
 *
 */
public class AssemblyAnalyzerTest {
    AssemblyAnalyzer analyzer;
    
    /**
     * Sets up the analyzer.
     * @throws Exception if anything goes sideways
     */
    @Before
    public void setUp() throws Exception {
        analyzer = new AssemblyAnalyzer();
        analyzer.initialize();
    }
    
    /**
     * Tests to make sure the name is correct.
     */
    @Test
    public void testGetName() {
        assertEquals("Assembly Analyzer", analyzer.getName());
    }
    
    @Test
    public void testAnalysis() throws Exception {
        File f = new File(AssemblyAnalyzerTest.class.getClassLoader().getResource("GrokAssembly.exe").getPath());
        Dependency d = new Dependency(f);
        analyzer.analyze(d, null);
        assertTrue(d.getVersionEvidence().getEvidence().contains(new Evidence("grokassembly", "version", "1.0.5140.29700", Confidence.HIGHEST)));
    }
    
    @Test
    public void testLog4Net() throws Exception {
        File f = new File(AssemblyAnalyzerTest.class.getClassLoader().getResource("log4net.dll").getPath());
        Dependency d = new Dependency(f);
        analyzer.analyze(d, null);
        assertTrue(d.getVersionEvidence().getEvidence().contains(new Evidence("grokassembly", "version", "1.2.13.0", Confidence.HIGHEST)));
        assertTrue(d.getVendorEvidence().getEvidence().contains(new Evidence("grokassembly", "vendor", "The Apache Software Foundation", Confidence.HIGH)));
        assertTrue(d.getProductEvidence().getEvidence().contains(new Evidence("grokassembly", "product", "log4net", Confidence.HIGH)));
    }
    
    @After
    public void tearDown() throws Exception {
        analyzer.close();
    }
}
