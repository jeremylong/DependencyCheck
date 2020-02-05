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
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;
import java.util.regex.Pattern;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;

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
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new CMakeAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
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
        try {
            analyzer.close();
        } finally {
            super.tearDown();
        }
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

    /**
     * Test whether expected evidence is gathered from OpenCV's CVDetectPython.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeCMakeListsPython() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "cmake/opencv/cmake/OpenCVDetectPython.cmake"));
        analyzer.analyze(result, null);

        //this one finds nothing so it falls through to the filename. Can we do better?
        assertEquals("numpy", result.getDisplayFileName());
    }

    private void assertProductEvidence(Dependency result, String product) {
        boolean found = false;
        for (Evidence e : result.getEvidence(EvidenceType.PRODUCT)) {
            if (product.equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue("Expected product evidence to contain \"" + product + "\".", found);
    }

    /**
     * Test whether expected version evidence is gathered from OpenCV's third
     * party cmake files.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeCMakeListsOpenCV3rdParty() throws AnalysisException, DatabaseException {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                    this, "cmake/opencv/3rdparty/ffmpeg/ffmpeg_version.cmake"));

            analyzer.analyze(result, engine);
            assertProductEvidence(result, "libavcodec");
            assertVersionEvidence(result, "55.18.102");
            assertFalse("ALIASOF_ prefix shouldn't be present.",
                    Pattern.compile("\\bALIASOF_\\w+").matcher(result.getEvidence(EvidenceType.PRODUCT).toString()).find());
            final Dependency[] dependencies = engine.getDependencies();
            assertEquals("Number of additional dependencies should be 4.", 4, dependencies.length);
            final Dependency last = dependencies[3];
            assertProductEvidence(last, "libavresample");
            assertVersionEvidence(last, "1.0.1");
        }
    }

    private void assertVersionEvidence(Dependency result, String version) {
        boolean found = false;
        for (Evidence e : result.getEvidence(EvidenceType.VERSION)) {
            if (version.equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue("Expected version evidence to contain \"" + version + "\".", found);
    }
}
