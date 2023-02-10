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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;
import org.apache.commons.lang3.ArrayUtils;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for PipfilelockAnalyzerTest.
 */
public class PipfilelockAnalyzerTest extends BaseDBTestCase {

    /**
     * The analyzer to test.
     */
    private PipfilelockAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new PipfilelockAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
        analyzer.prepare(null);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    @Override
    public void tearDown() throws Exception {
        analyzer.close();
        super.tearDown();
    }

    /**
     * Test of getName method, of class PipAnalyzer.
     */
    @Test
    public void testGetName() {
        assertEquals("Pipfile.lock Analyzer", analyzer.getName());
    }

    /**
     * Test of supportsExtension method, of class PipAnalyzer.
     */
    @Test
    public void testSupportsFiles() {
        assertFalse(analyzer.accept(new File("Pipfile")));
        assertTrue(analyzer.accept(new File("Pipfile.lock")));
    }

    @Test
    public void testAnalyzePackageLock() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "pip/Pipfile.lock"));
            engine.addDependency(result);
            analyzer.analyze(result, engine);
            assertFalse(ArrayUtils.contains(engine.getDependencies(), result));
            assertEquals(76, engine.getDependencies().length);
            boolean found = false;
            for (Dependency d : engine.getDependencies()) {
                if ("alabaster".equals(d.getName())) {
                    found = true;
                    assertEquals("0.7.12", d.getVersion());
                    assertThat(d.getDisplayFileName(), equalTo("alabaster:0.7.12"));
                    assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM, d.getEcosystem());
                    break;
                }
            }
            assertTrue("Expeced to find urllib3", found);
        }
    }
}
