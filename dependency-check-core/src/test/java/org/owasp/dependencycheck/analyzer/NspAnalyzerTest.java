package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.dependency.EvidenceType;

public class NspAnalyzerTest extends BaseTest {

    private NspAnalyzer analyzer;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new NspAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize(getSettings());
        analyzer.prepare(null);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        analyzer.close();
        super.tearDown();
    }

    @Test
    public void testGetName() {
        assertThat(analyzer.getName(), is("Node Security Platform Analyzer"));
    }

    @Test
    public void testSupportsFiles() {
        assertThat(analyzer.accept(new File("package.json")), is(true));
    }

    @Test
    public void testAnalyzePackage() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/package.json"));
        analyzer.analyze(result, null);

        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("owasp-nodejs-goat_project"));
        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("A tool to learn OWASP Top 10 for node.js developers"));
        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("1.3.0"));
    }

    @Test
    public void testAnalyzeEmpty() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/empty.json"));
        analyzer.analyze(result, null);

        assertEquals(result.getEvidence(EvidenceType.VENDOR).size(), 0);
        assertEquals(result.getEvidence(EvidenceType.PRODUCT).size(), 0);
        assertEquals(result.getEvidence(EvidenceType.VERSION).size(), 0);
    }

    @Test
    public void testAnalyzePackageJsonWithBundledDeps() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/bundled.deps.package.json"));
        analyzer.analyze(result, null);

        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("Philipp Dunkel <pip@pipobscure.com>"));
        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Native Access to Mac OS-X FSEvents"));
        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("1.1.1"));
    }

    @Test
    public void testAnalyzePackageJsonWithLicenseObject() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/license.obj.package.json"));
        analyzer.analyze(result, null);

        assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("Twitter, Inc."));
        assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("The most popular front-end framework for developing responsive, mobile first projects on the web"));
        assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("3.2.0"));
    }

    @Test
    public void testAnalyzePackageJsonInNodeModulesDirectory() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nodejs/node_modules/dns-sync/package.json"));
        analyzer.analyze(result, null);
        // node modules are not scanned - no evidence is collected
        assertTrue(result.size() == 0);
    }

    @Test
    public void testAnalyzeInvalidPackageMissingName() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/minimal-invalid.json"));
        analyzer.analyze(result, null);
        // Upon analysis, not throwing an exception in this case, is all that's required to pass this test
    }
}
