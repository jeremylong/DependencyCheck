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
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;

public class NspAnalyzerTest extends BaseTest {

    @Test
    public void testGetName() {
        NspAnalyzer analyzer = new NspAnalyzer();
        assertThat(analyzer.getName(), is("Node Security Platform Analyzer"));
    }

    @Test
    public void testSupportsFiles() {
        NspAnalyzer analyzer = new NspAnalyzer();
        assertThat(analyzer.accept(new File("package.json")), is(true));
    }

    @Test
    public void testAnalyzePackage() throws AnalysisException, InitializationException {
        try (Engine engine = new Engine(getSettings())) {
            NspAnalyzer analyzer = new NspAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/package.json"));
            analyzer.analyze(result, engine);

            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("owasp-nodejs-goat"));
            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("A tool to learn OWASP Top 10 for node.js developers"));
            assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("1.3.0"));
        }
    }

    @Test
    public void testAnalyzeEmpty() throws AnalysisException, InitializationException {
        try (Engine engine = new Engine(getSettings())) {
            NspAnalyzer analyzer = new NspAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/empty.json"));
            analyzer.analyze(result, engine);

            assertEquals(result.getEvidence(EvidenceType.VENDOR).size(), 0);
            assertEquals(result.getEvidence(EvidenceType.PRODUCT).size(), 0);
            assertEquals(result.getEvidence(EvidenceType.VERSION).size(), 0);
        }
    }

    @Test
    public void testAnalyzePackageJsonWithBundledDeps() throws AnalysisException, InitializationException {
        try (Engine engine = new Engine(getSettings())) {
            NspAnalyzer analyzer = new NspAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/bundled.deps.package.json"));
            analyzer.analyze(result, engine);

            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("Philipp Dunkel <pip@pipobscure.com>"));
            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Native Access to Mac OS-X FSEvents"));
            assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("1.1.1"));
        }
    }

    @Test
    public void testAnalyzePackageJsonWithLicenseObject() throws AnalysisException, InitializationException {
        try (Engine engine = new Engine(getSettings())) {
            NspAnalyzer analyzer = new NspAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/license.obj.package.json"));
            analyzer.analyze(result, engine);

            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("Twitter, Inc."));
            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("The most popular front-end framework for developing responsive, mobile first projects on the web"));
            assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("3.2.0"));
        }
    }

    @Test
    public void testAnalyzePackageJsonInNodeModulesDirectory() throws AnalysisException, InitializationException {
        try (Engine engine = new Engine(getSettings())) {
            NspAnalyzer analyzer = new NspAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nodejs/node_modules/dns-sync/package.json"));
            analyzer.analyze(result, engine);
            // package.json adds 5 bits of evidence
            assertTrue(result.size() == 5);
            // but no vulnerabilities were cited
            assertTrue(result.getVulnerabilities().isEmpty());
        }
    }

    @Test
    public void testAnalyzeInvalidPackageMissingName() throws AnalysisException, InitializationException {
        try (Engine engine = new Engine(getSettings())) {
            NspAnalyzer analyzer = new NspAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nsp/minimal-invalid.json"));
            analyzer.analyze(result, engine);
            // Upon analysis, not throwing an exception in this case, is all that's required to pass this test
        }
    }
}
