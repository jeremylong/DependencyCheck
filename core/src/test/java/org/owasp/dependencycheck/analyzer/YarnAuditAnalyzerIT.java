package org.owasp.dependencycheck.analyzer;

import org.junit.Assume;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import static org.junit.Assert.assertTrue;

public class YarnAuditAnalyzerIT extends BaseTest {

    @Test
    public void testAnalyzePackageYarn() throws AnalysisException, InitializationException, InvalidSettingException {
        
        //Assume.assumeThat(getSettings().getBoolean(Settings.KEYS.ANALYZER_YARN_AUDIT_ENABLED), is(true));
        try (Engine engine = new Engine(getSettings())) {
            YarnAuditAnalyzer analyzer = new YarnAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "yarnaudit/yarn.lock"));
            analyzer.analyze(toScan, engine);
            boolean found = false;
            assertTrue("More then 1 dependency should be identified", 1 < engine.getDependencies().length);
            for (Dependency result : engine.getDependencies()) {
                if ("yarn.lock?uglify-js".equals(result.getFileName())) {
                    found = true;
                    assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("uglify-js"));
                    assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("uglify-js"));
                    assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("3.12.4"));
                    assertTrue(result.isVirtual());
                }
            }
            assertTrue("Uglify was not found", found);
        } catch (InitializationException ex) {
            //yarn is not installed - skip the test case.
            Assume.assumeNoException(ex);
        }
    }
}
