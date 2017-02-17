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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for AutoconfAnalyzer. The test resources under autoconf/ were obtained from outside open source software projects.
 * Links to those projects are given below.
 *
 * @author Dale Visser
 * @see <a href="http://readable.sourceforge.net/">Readable Lisp S-expressions Project</a>
 * @see <a href="https://gnu.org/software/binutils/">GNU Binutils</a>
 * @see <a href="https://gnu.org/software/ghostscript/">GNU Ghostscript</a>
 */
public class AutoconfAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private AutoconfAnalyzer analyzer;

    private void assertCommonEvidence(Dependency result, String product,
            String version, String vendor) {
        assertProductAndVersion(result, product, version);
        assertTrue("Expected vendor evidence to contain \"" + vendor + "\".",
                result.getVendorEvidence().toString().contains(vendor));
    }

    private void assertProductAndVersion(Dependency result, String product,
            String version) {
        assertTrue("Expected product evidence to contain \"" + product + "\".",
                result.getProductEvidence().toString().contains(product));
        assertTrue("Expected version evidence to contain \"" + version + "\".",
                result.getVersionEvidence().toString().contains(version));
    }

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        analyzer = new AutoconfAnalyzer();
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
     * Test whether expected evidence is gathered from Ghostscript's configure.ac.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeConfigureAC1() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "autoconf/ghostscript/configure.ac"));
        analyzer.analyze(result, null);
        assertCommonEvidence(result, "ghostscript", "8.62.0", "gnu");
    }

    /**
     * Test whether expected evidence is gathered from Readable's configure.ac.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeConfigureAC2() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "autoconf/readable-code/configure.ac"));
        analyzer.analyze(result, null);
        assertReadableCodeEvidence(result);
    }

    private void assertReadableCodeEvidence(final Dependency result) {
        assertCommonEvidence(result, "readable", "1.0.7", "dwheeler");
        final String url = "http://readable.sourceforge.net/";
        assertTrue("Expected product evidence to contain \"" + url + "\".",
                result.getVendorEvidence().toString().contains(url));
    }

    /**
     * Test whether expected evidence is gathered from GNU Binutil's configure.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeConfigureScript() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "autoconf/binutils/configure"));
        analyzer.analyze(result, null);
        assertProductAndVersion(result, "binutils", "2.25.51");
    }

    /**
     * Test whether expected evidence is gathered from GNU Ghostscript's configure.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeReadableConfigureScript() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "autoconf/readable-code/configure"));
        analyzer.analyze(result, null);
        assertReadableCodeEvidence(result);
    }

    /**
     * Test of getName method, of {@link AutoconfAnalyzer}.
     */
    @Test
    public void testGetName() {
        assertEquals("Analyzer name wrong.", "Autoconf Analyzer",
                analyzer.getName());
    }

    /**
     * Test of {@link AutoconfAnalyzer#accept(File)}.
     */
    @Test
    public void testSupportsFileExtension() {
        assertTrue("Should support \"ac\" extension.",
                analyzer.accept(new File("configure.ac")));
        assertTrue("Should support \"in\" extension.",
                analyzer.accept(new File("configure.in")));
        assertTrue("Should support \"configure\" extension.",
                analyzer.accept(new File("configure")));
    }
}
