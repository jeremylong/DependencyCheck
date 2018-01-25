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
import org.owasp.dependencycheck.dependency.Evidence;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.owasp.dependencycheck.dependency.EvidenceType;

/**
 * Unit tests for PythonDistributionAnalyzer.
 *
 * @author Dale Visser
 */
public class PythonDistributionAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private PythonDistributionAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new PythonDistributionAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
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
     * Test of getName method, of class PythonDistributionAnalyzer.
     */
    @Test
    public void testGetName() {
        assertEquals("Analyzer name wrong.", "Python Distribution Analyzer",
                analyzer.getName());
    }

    /**
     * Test of supportsExtension method, of class PythonDistributionAnalyzer.
     */
    @Test
    public void testSupportsFiles() {
        assertTrue("Should support \"whl\" extension.",
                analyzer.accept(new File("test.whl")));
        assertTrue("Should support \"egg\" extension.",
                analyzer.accept(new File("test.egg")));
        assertTrue("Should support \"zip\" extension.",
                analyzer.accept(new File("test.zip")));
        assertTrue("Should support \"METADATA\" extension.",
                analyzer.accept(new File("METADATA")));
        assertTrue("Should support \"PKG-INFO\" extension.",
                analyzer.accept(new File("PKG-INFO")));
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     */
    @Test
    public void testAnalyzeWheel() {
        try {
            djangoAssertions(new Dependency(BaseTest.getResourceAsFile(this,
                    "python/Django-1.7.2-py2.py3-none-any.whl")));
        } catch (AnalysisException ex) {
            fail(ex.getMessage());
        }
    }

    /**
     * Test of inspect method, of class PythonDistributionAnalyzer.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeSitePackage() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                this, "python/site-packages/Django-1.7.2.dist-info/METADATA"));
        djangoAssertions(result);
        }

    private void djangoAssertions(final Dependency result)
            throws AnalysisException {
        boolean found = false;
        analyzer.analyze(result, null);
        assertTrue("Expected vendor evidence to contain \"djangoproject\".",
                result.getEvidence(EvidenceType.VENDOR).toString().contains("djangoproject"));
        for (final Evidence e : result.getEvidence(EvidenceType.VERSION)) {
            if ("Version".equals(e.getName()) && "1.7.2".equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue("Version 1.7.2 not found in Django dependency.", found);
        assertEquals("1.7.2",result.getVersion());
        assertEquals("Django",result.getName());
        assertEquals("Django:1.7.2",result.getDisplayFileName());
        assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM,result.getEcosystem());
    }

    @Test
    public void testAnalyzeEggInfoFolder() {
        try {
            eggtestAssertions(this, "python/site-packages/EggTest.egg-info/PKG-INFO");
        } catch (AnalysisException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testAnalyzeEggArchive() {
        try {
            eggtestAssertions(this, "python/dist/EggTest-0.0.1-py2.7.egg");
        } catch (AnalysisException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testAnalyzeEggArchiveNamedZip() {
        try {
            eggtestAssertions(this, "python/dist/EggTest-0.0.1-py2.7.zip");
        } catch (AnalysisException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testAnalyzeEggFolder() {
        try {
            eggtestAssertions(this, "python/site-packages/EggTest-0.0.1-py2.7.egg/EGG-INFO/PKG-INFO");
        } catch (AnalysisException ex) {
            fail(ex.getMessage());
        }
    }

    public void eggtestAssertions(Object context, final String resource) throws AnalysisException {
        boolean found = false;
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(
                context, resource));
        analyzer.analyze(result, null);
        assertTrue("Expected vendor evidence to contain \"example\".", result
                .getEvidence(EvidenceType.VENDOR).toString().contains("example"));
        for (final Evidence e : result.getEvidence(EvidenceType.VERSION)) {
            if ("0.0.1".equals(e.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue("Version 0.0.1 not found in EggTest dependency.", found);
        assertEquals("0.0.1",result.getVersion());
        assertEquals("EggTest",result.getName());
        assertEquals("EggTest:0.0.1",result.getDisplayFileName());
        assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM,result.getEcosystem());
    }
}
