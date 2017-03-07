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

import mockit.Mock;
import mockit.MockUp;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;

import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.regex.Pattern;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for CmakeAnalyzer.
 *
 * @author Dale Visser
 */
public class CMakeAnalyzerTest extends BaseDBTestCase {

    /**
     * The package analyzer to test.
     */
    private CMakeAnalyzer analyzer;

    /**
     * Setup the CmakeAnalyzer.
     *
     * @throws Exception if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        analyzer = new CMakeAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize();
    }

    /**
     * Cleanup any resources used.
     *
     * @throws Exception if there is a problem
     */
    @After
    public void tearDown() throws Exception {
        analyzer.close();
        analyzer = null;
    }

    /**
     * Test of getName method, of class PythonPackageAnalyzer.
     */
    @Test
    public void testGetName() {
        assertThat(analyzer.getName(), is(equalTo("CMake Analyzer")));
    }

    /**
     * Test of supportsExtension method, of class PythonPackageAnalyzer.
     */
    @Test
    public void testAccept() {
        assertTrue("Should support \"CMakeLists.txt\" name.",
                analyzer.accept(new File("CMakeLists.txt")));
        assertTrue("Should support \"cmake\" extension.",
                analyzer.accept(new File("test.cmake")));
    }

    /**
     * Test whether expected evidence is gathered from OpenCV's CMakeLists.txt.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeCMakeListsOpenCV() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "cmake/opencv/CMakeLists.txt"));
        analyzer.analyze(result, null);
        final String product = "OpenCV";
        assertProductEvidence(result, product);
    }

    /**
     * Test whether expected evidence is gathered from OpenCV's CMakeLists.txt.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeCMakeListsZlib() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "cmake/zlib/CMakeLists.txt"));
        analyzer.analyze(result, null);
        final String product = "zlib";
        assertProductEvidence(result, product);
    }

    private void assertProductEvidence(Dependency result, String product) {
        assertTrue("Expected product evidence to contain \"" + product + "\".",
                result.getProductEvidence().toString().contains(product));
    }

    /**
     * Test whether expected version evidence is gathered from OpenCV's third party cmake files.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeCMakeListsOpenCV3rdParty() throws AnalysisException, DatabaseException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "cmake/opencv/3rdparty/ffmpeg/ffmpeg_version.cmake"));
        final Engine engine = new Engine();
        analyzer.analyze(result, engine);
        assertProductEvidence(result, "libavcodec");
        assertVersionEvidence(result, "55.18.102");
        assertFalse("ALIASOF_ prefix shouldn't be present.",
                Pattern.compile("\\bALIASOF_\\w+").matcher(result.getProductEvidence().toString()).find());
        final List<Dependency> dependencies = engine.getDependencies();
        assertEquals("Number of additional dependencies should be 4.", 4, dependencies.size());
        final Dependency last = dependencies.get(3);
        assertProductEvidence(last, "libavresample");
        assertVersionEvidence(last, "1.0.1");
    }

    private void assertVersionEvidence(Dependency result, String version) {
        assertTrue("Expected version evidence to contain \"" + version + "\".",
                result.getVersionEvidence().toString().contains(version));
    }

    @Test(expected = InitializationException.class)
    public void analyzerIsDisabledInCaseOfMissingMessageDigest() throws InitializationException {
        new MockUp<MessageDigest>() {
            @Mock
            MessageDigest getInstance(String ignore) throws NoSuchAlgorithmException {
                throw new NoSuchAlgorithmException();
            }
        };

        analyzer = new CMakeAnalyzer();
        analyzer.setFilesMatched(true);
        assertTrue(analyzer.isEnabled());
        analyzer.initialize();

        assertFalse(analyzer.isEnabled());
    }
}
