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
 * Copyright (c) 2015 The OWASP Foundatio. All Rights Reserved.
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
 * Unit tests for NodePackageAnalyzer.
 *
 * @author Dale Visser
 */
public class ComposerLockAnalyzerTest extends BaseDBTestCase {

    /**
     * The analyzer to test.
     */
    private ComposerLockAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new ComposerLockAnalyzer();
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
     * Test of getName method, of class ComposerLockAnalyzer.
     */
    @Test
    public void testGetName() {
        assertEquals("Composer.lock analyzer", analyzer.getName());
    }

    /**
     * Test of supportsExtension method, of class ComposerLockAnalyzer.
     */
    @Test
    public void testSupportsFiles() {
        assertTrue(analyzer.accept(new File("composer.lock")));
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzePackageJson() throws Exception {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                    "composer.lock"));
            //simulate normal operation when the composer.lock is already added to the engine as a dependency
            engine.addDependency(result);
            analyzer.analyze(result, engine);
            //make sure the redundant composer.lock is removed
            assertFalse(ArrayUtils.contains(engine.getDependencies(), result));
            assertEquals(30, engine.getDependencies().length);
            boolean found = false;
            for (Dependency d : engine.getDependencies()) {
                if ("classpreloader".equals(d.getName())) {
                    found = true;
                    assertEquals("2.0.0", d.getVersion());
                    assertThat(d.getDisplayFileName(), equalTo("classpreloader:2.0.0"));
                    assertEquals(ComposerLockAnalyzer.DEPENDENCY_ECOSYSTEM, d.getEcosystem());
                }
            }
            assertTrue("Expeced to find classpreloader", found);
        }
    }
}
