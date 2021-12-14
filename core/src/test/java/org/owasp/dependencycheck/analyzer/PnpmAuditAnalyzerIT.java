package org.owasp.dependencycheck.analyzer;

import org.junit.Assume;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;

import static org.junit.Assert.assertTrue;
import org.junit.Ignore;

public class PnpmAuditAnalyzerIT extends BaseTest {

    @Test
    @Ignore("unfortunately pnpm and brew are somewhat broken on my machine atm...")
    public void testAnalyzePackagePnpm() throws AnalysisException {

        try (Engine engine = new Engine(getSettings())) {
            PnpmAuditAnalyzer analyzer = new PnpmAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            analyzer.setEnabled(true);
            final Dependency toScan = new Dependency(BaseTest.getResourceAsFile(this, "pnpmaudit/pnpm-lock.yaml"));
            analyzer.analyze(toScan, engine);
            boolean found = false;
            assertTrue("More than 1 dependency should be identified", 1 < engine.getDependencies().length);
            for (Dependency result : engine.getDependencies()) {
                if ("pnpm-lock.yaml?dns-sync".equals(result.getFileName())) {
                    found = true;
                    assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("dns-sync"));
                    assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("dns-sync"));
                    assertTrue(result.isVirtual());
                }
            }
            assertTrue("dns-sync was not found", found);
        } catch (InitializationException ex) {
            //yarn is not installed - skip the test case.
            Assume.assumeNoException(ex);
        }
    }
}
