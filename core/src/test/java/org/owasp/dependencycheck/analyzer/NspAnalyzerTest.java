package org.owasp.dependencycheck.analyzer;

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
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "nsp/package.json"));
            analyzer.analyze(toScan, engine);
            boolean found = false;
            assertTrue("Mpre then 1 dependency should be identified", 1 < engine.getDependencies().length);
            for (Dependency result : engine.getDependencies()) {
                if ("package.json?uglify-js".equals(result.getFileName())) {
                    found = true;
                    assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("uglify-js"));
                    assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("uglify-js"));
                    assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("2.4.24"));
                    assertTrue(result.isVirtual());
                }
            }
            assertTrue("Uglify was not found", found);
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
    public void testAnalyzePackageJsonInNodeModulesDirectory() throws AnalysisException, InitializationException {
        try (Engine engine = new Engine(getSettings())) {
            NspAnalyzer analyzer = new NspAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "nodejs/node_modules/dns-sync/package.json"));
            engine.addDependency(toScan);
            analyzer.analyze(toScan, engine);
            assertEquals("No dependencies should exist", 0, engine.getDependencies().length);
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
        } catch (Throwable ex) {
            fail("This test should not throw an exception");
            throw ex;
        }
    }
}
