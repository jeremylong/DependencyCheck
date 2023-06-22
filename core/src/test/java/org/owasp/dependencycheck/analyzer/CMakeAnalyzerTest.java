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
import java.util.HashMap;
import java.util.Map;
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

    @Test
    public void testRemoveSelfReferences() {
        // Given
        Map<String, String> input = new HashMap<>();
        input.put("Deflate_OLD_FIND_LIBRARY_PREFIXES", "${CMAKE_FIND_LIBRARY_PREFIXES}");
        input.put("Deflate_INCLUDE_DIRS", "${Deflate_INCLUDE_DIR}");
        input.put("Deflate_LIBRARIES", "${Deflate_LIBRARY}");
        input.put("Deflate_MINOR_VERSION", "${Deflate_VERSION_MINOR}");
        input.put("Deflate_VERSION_STRING", "${Deflate_MAJOR_VERSION}.${Deflate_MINOR_VERSION}");
        input.put("CMAKE_FIND_LIBRARY_PREFIXES", "${Deflate_OLD_FIND_LIBRARY_PREFIXES}");
        input.put("Deflate_MAJOR_VERSION", "${Deflate_VERSION_MAJOR}");

        Map<String, String> expectedOutput = new HashMap<>();
        expectedOutput.put("Deflate_INCLUDE_DIRS", "${Deflate_INCLUDE_DIR}");
        expectedOutput.put("Deflate_LIBRARIES", "${Deflate_LIBRARY}");
        expectedOutput.put("Deflate_MINOR_VERSION", "${Deflate_VERSION_MINOR}");
        expectedOutput.put("Deflate_VERSION_STRING", "${Deflate_MAJOR_VERSION}.${Deflate_MINOR_VERSION}");
        expectedOutput.put("Deflate_MAJOR_VERSION", "${Deflate_VERSION_MAJOR}");

        // When
        Map<String, String> output = analyzer.removeSelfReferences(input);

        // Then
        assertEquals(expectedOutput, output);
    }

    @Test
    public void testRemoveSelfReferences2() {
        // Given
        Map<String, String> input = new HashMap<>();
        input.put("FLTK2_DIR", "${FLTK2_INCLUDE_DIR}");
        input.put("FLTK2_LIBRARY_SEARCH_PATH", "");
        input.put("FLTK2_INCLUDE_DIR", "${FLTK2_DIR}");
        input.put("FLTK2_IMAGES_LIBS", "");
        input.put("FLTK2_DIR_SEARCH", "");
        input.put("FLTK2_WRAP_UI", "1");
        input.put("FLTK2_FOUND", "0");
        input.put("FLTK2_IMAGES_LIBRARY", "fltk2_images");
        input.put("FLTK2_PLATFORM_DEPENDENT_LIBS", "import32");
        input.put("FLTK_FLUID_EXECUTABLE", "${FLTK2_FLUID_EXECUTABLE}");
        input.put("FLTK2_INCLUDE_SEARCH_PATH", "");
        input.put("FLTK2_LIBRARY", "${FLTK2_LIBRARIES}");
        input.put("FLTK2_BUILT_WITH_CMAKE", "1");
        input.put("FLTK2_INCLUDE_PATH", "${FLTK2_INCLUDE_DIR}");
        input.put("FLTK2_GL_LIBRARY", "fltk2_gl");
        input.put("FLTK2_FLUID_EXE", "${FLTK2_FLUID_EXECUTABLE}");
        input.put("HAS_FLTK2", "${FLTK2_FOUND}");
        input.put("FLTK2_BASE_LIBRARY", "fltk2");


        Map<String, String> expectedOutput = new HashMap<>();
        expectedOutput.put("FLTK2_LIBRARY_SEARCH_PATH", "");
        expectedOutput.put("FLTK2_IMAGES_LIBS", "");
        expectedOutput.put("FLTK2_DIR_SEARCH", "");
        expectedOutput.put("FLTK2_WRAP_UI", "1");
        expectedOutput.put("FLTK2_FOUND", "0");
        expectedOutput.put("FLTK2_IMAGES_LIBRARY", "fltk2_images");
        expectedOutput.put("FLTK2_PLATFORM_DEPENDENT_LIBS", "import32");
        expectedOutput.put("FLTK_FLUID_EXECUTABLE", "${FLTK2_FLUID_EXECUTABLE}");
        expectedOutput.put("FLTK2_INCLUDE_SEARCH_PATH", "");
        expectedOutput.put("FLTK2_LIBRARY", "${FLTK2_LIBRARIES}");
        expectedOutput.put("FLTK2_BUILT_WITH_CMAKE", "1");
        expectedOutput.put("FLTK2_GL_LIBRARY", "fltk2_gl");
        expectedOutput.put("FLTK2_FLUID_EXE", "${FLTK2_FLUID_EXECUTABLE}");
        expectedOutput.put("HAS_FLTK2", "${FLTK2_FOUND}");
        expectedOutput.put("FLTK2_BASE_LIBRARY", "fltk2");

        // When
        Map<String, String> output = analyzer.removeSelfReferences(input);

        // Then
        assertEquals(expectedOutput, output);
    }

    /**
     * Test the analyzer does not end up in an infinite loop when a temp
     * variable is used to store old value and then restore it afterwards.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeCMakeTempVariable() throws AnalysisException {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                    this, "cmake/libtiff/FindDeflate.cmake"));
            analyzer.analyze(result, engine);

            assertEquals("FindDeflate.cmake", result.getFileName());
        }
    }

    @Test
    public void testAnalyzeCMakeInfiniteLoop() throws AnalysisException {
        try (Engine engine = new Engine(getSettings())) {
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                    this, "cmake/cmake-modules/FindFLTK2.cmake"));
            analyzer.analyze(result, engine);

            assertEquals("FindFLTK2.cmake", result.getFileName());
        }
    }
}
