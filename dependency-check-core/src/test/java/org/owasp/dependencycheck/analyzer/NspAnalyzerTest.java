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

public class NspAnalyzerTest extends BaseTest {
    private NspAnalyzer analyzer;

    @Before
    public void setUp() throws Exception {
        analyzer = new NspAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize();
    }

    @After
    public void tearDown() throws Exception {
        analyzer.close();
        analyzer = null;
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

        assertEquals(result.getVendorEvidence().toString(), "owasp-nodejs-goat_project ");
        assertEquals(result.getProductEvidence().toString(), "A tool to learn OWASP Top 10 for node.js developers owasp-nodejs-goat ");
        assertEquals(result.getVersionEvidence().toString(), "1.3.0 ");
    }
    @Test
    public void testAnalyzeEmpty() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/empty.json"));
        analyzer.analyze(result, null);

        assertEquals(result.getVendorEvidence().size(), 0);
        assertEquals(result.getProductEvidence().size(), 0);
        assertEquals(result.getVersionEvidence().size(), 0);
    }

    @Test
    public void testAnalyzePackageJsonWithBundledDeps() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/bundled.deps.package.json"));
        analyzer.analyze(result, null);

        assertEquals(result.getVendorEvidence().toString(), "Philipp Dunkel <pip@pipobscure.com> fsevents_project ");
        assertEquals(result.getProductEvidence().toString(), "Native Access to Mac OS-X FSEvents fsevents ");
        assertEquals(result.getVersionEvidence().toString(), "1.1.1 ");
    }

    @Test
    public void testAnalyzePackageJsonWithLicenseObject() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/license.obj.package.json"));
        analyzer.analyze(result, null);

        assertEquals(result.getVendorEvidence().toString(), "Twitter, Inc. bootstrap_project ");
        assertEquals(result.getProductEvidence().toString(), "The most popular front-end framework for developing responsive, mobile first projects on the web. bootstrap ");
        assertEquals(result.getVersionEvidence().toString(), "3.2.0 ");
    }

    @Test
    public void testAnalyzePackageJsonInNodeModulesDirectory() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nodejs/node_modules/dns-sync/package.json"));
        analyzer.analyze(result, null);
        final String vendorString = result.getVendorEvidence().toString();

        // node modules are not scanned
        assertTrue(vendorString.isEmpty());
        assertEquals(result.getProductEvidence().size(), 0);
        assertEquals(result.getVersionEvidence().size(), 0);
    }
}
