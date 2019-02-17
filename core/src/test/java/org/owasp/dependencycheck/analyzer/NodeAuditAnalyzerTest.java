package org.owasp.dependencycheck.analyzer;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import java.io.File;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;
import org.junit.Assume;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

public class NodeAuditAnalyzerTest extends BaseTest {

    @Test
    public void testGetName() {
        NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
        assertThat(analyzer.getName(), is("Node Audit Analyzer"));
    }

    @Test
    public void testSupportsFiles() {
        NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
        assertThat(analyzer.accept(new File("package-lock.json")), is(true));
        assertThat(analyzer.accept(new File("npm-shrinkwrap.json")), is(true));
        assertThat(analyzer.accept(new File("package.json")), is(false));
    }

    @Test
    public void testAnalyzePackage() throws AnalysisException, InitializationException, InvalidSettingException {
        Assume.assumeThat(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED), is(true));
        try (Engine engine = new Engine(getSettings())) {
            NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "nodeaudit/package-lock.json"));
            analyzer.analyze(toScan, engine);
            boolean found = false;
            assertTrue("Mpre then 1 dependency should be identified", 1 < engine.getDependencies().length);
            for (Dependency result : engine.getDependencies()) {
                if ("package-lock.json?uglify-js".equals(result.getFileName())) {
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
    public void testAnalyzeEmpty() throws AnalysisException, InitializationException, InvalidSettingException {
        Assume.assumeThat(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED), is(true));
        try (Engine engine = new Engine(getSettings())) {
            NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "nodeaudit/empty.json"));
            analyzer.analyze(result, engine);

            assertEquals(0, result.getEvidence(EvidenceType.VENDOR).size());
            assertEquals(0, result.getEvidence(EvidenceType.PRODUCT).size());
            assertEquals(0, result.getEvidence(EvidenceType.VERSION).size());
        }
    }

    @Test
    public void testAnalyzePackageJsonInNodeModulesDirectory() throws AnalysisException, InitializationException, InvalidSettingException {
        Assume.assumeThat(getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED), is(true));
        try (Engine engine = new Engine(getSettings())) {
            NodeAuditAnalyzer analyzer = new NodeAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "nodejs/node_modules/dns-sync/package.json"));
            engine.addDependency(toScan);
            analyzer.analyze(toScan, engine);
            assertEquals("No dependencies should exist", 0, engine.getDependencies().length);
        }
    }

}
