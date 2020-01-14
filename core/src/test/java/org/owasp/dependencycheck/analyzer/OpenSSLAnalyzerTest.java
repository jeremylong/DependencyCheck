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
 * Copyright (c) 2015 Institute for Defense Analyses. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.owasp.dependencycheck.dependency.EvidenceType;

/**
 * Unit tests for OpenSSLAnalyzerAnalyzer.
 *
 * @author Dale Visser
 */
public class OpenSSLAnalyzerTest extends BaseTest {

    /**
     * The package analyzer to test.
     */
    private OpenSSLAnalyzer analyzer;

    /**
     * Setup the {@link OpenSSLAnalyzer}.
     *
     * @throws Exception if there is a problem
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new OpenSSLAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
        analyzer.prepare(null);
    }

    /**
     * Cleanup any resources used.
     *
     * @throws Exception if there is a problem
     */
    @After
    @Override
    public void tearDown() throws Exception {
        analyzer.close();
        super.tearDown();
    }

    /**
     * Test of getName method, of class OpenSSLAnalyzer.
     */
    @Test
    public void testGetName() {
        assertEquals("Analyzer name wrong.", "OpenSSL Source Analyzer", analyzer.getName());
    }

    /**
     * Test of supportsExtension method, of class PythonPackageAnalyzer.
     */
    @Test
    public void testAccept() {
        assertTrue("Should support files named \"opensslv.h\".",
                analyzer.accept(new File("opensslv.h")));
    }

    @Test
    public void testVersionConstantExamples() {
        final long[] constants = {0x1000203fL, 0x00903000, 0x00903001, 0x00903002l, 0x0090300f, 0x0090301f, 0x0090400f, 0x102031af};
        final String[] versions = {"1.0.2c",
            "0.9.3-dev",
            "0.9.3-beta1",
            "0.9.3-beta2",
            "0.9.3",
            "0.9.3a",
            "0.9.4",
            "1.2.3z"};
        assertEquals(constants.length, versions.length);
        for (int i = 0; i < constants.length; i++) {
            assertEquals(versions[i], OpenSSLAnalyzer.getOpenSSLVersion(constants[i]));
        }
    }

    @Test
    public void testOpenSSLVersionHeaderFile() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this,
                "openssl/opensslv.h"));
        analyzer.analyze(result, null);
        assertThat(result.getEvidence(EvidenceType.PRODUCT).toString(), containsString("OpenSSL"));
        assertThat(result.getEvidence(EvidenceType.VENDOR).toString(), containsString("OpenSSL"));
        assertThat(result.getEvidence(EvidenceType.VERSION).toString(), containsString("1.0.2c"));
    }
}
