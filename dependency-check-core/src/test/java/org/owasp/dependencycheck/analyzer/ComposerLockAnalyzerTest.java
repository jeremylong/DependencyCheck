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

import mockit.Mock;
import mockit.MockUp;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;

import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
    public void setUp() throws Exception {
        analyzer = new ComposerLockAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize();
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    public void tearDown() throws Exception {
        analyzer.close();
        analyzer = null;
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
        final Engine engine = new Engine();
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "composer.lock"));
        analyzer.analyze(result, engine);
    }


    @Test(expected = InitializationException.class)
    public void analyzerIsDisabledInCaseOfMissingMessageDigest() throws InitializationException {
        new MockUp<MessageDigest>() {
            @Mock
            MessageDigest getInstance(String ignore) throws NoSuchAlgorithmException {
                throw new NoSuchAlgorithmException();
            }
        };

        analyzer = new ComposerLockAnalyzer();
        analyzer.setFilesMatched(true);
        assertTrue(analyzer.isEnabled());
        analyzer.initialize();

        assertFalse(analyzer.isEnabled());
    }
}
