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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashSet;

import org.apache.commons.lang.StringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;

/**
 * Unit tests for PythonDistributionAnalyzer.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class PythonDistributionAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    PythonDistributionAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        analyzer = new PythonDistributionAnalyzer();
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
     * Test of getName method, of class PythonDistributionAnalyzer.
     */
    @Test
    public void testGetName() {
        assertEquals("Analyzer name wrong.", "Python Distribution Analyzer",
                analyzer.getName());
    }

    /**
     * Test of getSupportedExtensions method, of class PythonDistributionAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        final String[] expected = {"whl", "egg", "zip", "METADATA", "PKG-INFO"};
        assertEquals("Supported extensions should just have the following: "
                + StringUtils.join(expected, ", "),
                new HashSet<String>(Arrays.asList(expected)),
                analyzer.getSupportedExtensions());
    }

    /**
     * Test of supportsExtension method, of class PythonDistributionAnalyzer.
     */
    @Test
    public void testSupportsExtension() {
        assertTrue("Should support \"whl\" extension.",
                analyzer.supportsExtension("whl"));
        assertTrue("Should support \"egg\" extension.",
                analyzer.supportsExtension("egg"));
        assertTrue("Should support \"zip\" extension.",
                analyzer.supportsExtension("zip"));
        assertTrue("Should support \"METADATA\" extension.",
                analyzer.supportsExtension("METADATA"));
        assertTrue("Should support \"PKG-INFO\" extension.",
                analyzer.supportsExtension("PKG-INFO"));
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeWheel() throws AnalysisException {
        djangoAssertions(new Dependency(BaseTest.getResourceAsFile(this,
                "python/Django-1.7.2-py2.py3-none-any.whl")));
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeSitePackage() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "python/site-packages/Django-1.7.2.dist-info/METADATA"));
        djangoAssertions(result);
        assertEquals("Django-1.7.2.dist-info/METADATA", result.getDisplayFileName());
    }

    private void djangoAssertions(final Dependency result)
            throws AnalysisException {
        boolean found = false;
        analyzer.analyze(result, null);
        assertTrue("Expected vendor evidence to contain \"djangoproject\".",
                result.getVendorEvidence().toString().contains("djangoproject"));
        for (final Evidence e : result.getVersionEvidence()) {
            if ("Version".equals(e.getName()) && "1.7.2".equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue("Version 1.7.2 not found in Django dependency.", found);
    }

    @Test
    public void testAnalyzeEggInfoFolder() throws AnalysisException {
        eggtestAssertions(this, "python/site-packages/EggTest.egg-info/PKG-INFO");
    }

    @Test
    public void testAnalyzeEggArchive() throws AnalysisException {
        eggtestAssertions(this, "python/dist/EggTest-0.0.1-py2.7.egg");
    }

    @Test
    public void testAnalyzeEggArchiveNamedZip() throws AnalysisException {
        eggtestAssertions(this, "python/dist/EggTest-0.0.1-py2.7.zip");
    }

    @Test
    public void testAnalyzeEggFolder() throws AnalysisException {
        eggtestAssertions(this, "python/site-packages/EggTest-0.0.1-py2.7.egg/EGG-INFO/PKG-INFO");
    }

    public void eggtestAssertions(Object context, final String resource) throws AnalysisException {
        boolean found = false;
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                context, resource));
        analyzer.analyze(result, null);
        assertTrue("Expected vendor evidence to contain \"example\".", result
                .getVendorEvidence().toString().contains("example"));
        for (final Evidence e : result.getVersionEvidence()) {
            if ("0.0.1".equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue("Version 0.0.1 not found in EggTest dependency.", found);
    }
}
