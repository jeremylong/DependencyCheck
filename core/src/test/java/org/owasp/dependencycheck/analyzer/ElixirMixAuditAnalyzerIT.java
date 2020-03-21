package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.*;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

public class ElixirMixAuditAnalyzerIT extends BaseDBTestCase {

    private static final Logger LOGGER = LoggerFactory.getLogger(ElixirMixAuditAnalyzerIT.class);


    private ElixirMixAuditAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        analyzer = new ElixirMixAuditAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    @Override
    public void tearDown() throws Exception {
        if (analyzer != null) {
            analyzer.close();
            analyzer = null;
        }
        super.tearDown();
    }


    /**
     * Test Elixir MixAudit analysis.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalysis() throws AnalysisException, DatabaseException {
        try (Engine engine = new Engine(getSettings())) {
            engine.openDatabase();
            analyzer.prepare(engine);
            final String resource = "elixir/vulnerable/mix.lock";
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, resource));
            analyzer.analyze(result, engine);

            final Dependency[] dependencies = engine.getDependencies();
            assertEquals("should be one result exactly", 1, dependencies.length);

            Dependency d = dependencies[0];
            assertTrue(d.isVirtual());
            assertEquals("plug:1.3.4", d.getPackagePath());
            assertEquals("1.3.4", d.getVersion());
            assertEquals("plug", d.getName());

            Evidence packageEvidence = d.getEvidence(EvidenceType.PRODUCT).iterator().next();
            assertEquals("Package", packageEvidence.getName());
            assertEquals("plug", packageEvidence.getValue());

            Evidence versionEvidence = d.getEvidence(EvidenceType.VERSION).iterator().next();
            assertEquals("Version", versionEvidence.getName());
            assertEquals("1.3.4", versionEvidence.getValue());

            assertTrue(d.getFilePath().endsWith(resource));
            assertTrue(d.getFileName().equals("mix.lock"));

            Vulnerability v = d.getVulnerabilities().iterator().next();
            assertEquals("2018-1000883", v.getName());
            assertEquals("Cookie headers were not validated\n", v.getDescription());
            assertEquals(-1.0f, v.getCvssV2().getScore(), 0.0);

            VulnerableSoftware s = v.getVulnerableSoftware().iterator().next();
            assertEquals("cpe:2.3:a:plug_project:plug:1.3.4:*:*:*:*:*:*:*", s.toString());

        } catch (InitializationException | DatabaseException | AnalysisException e) {
            LOGGER.warn("Exception setting up ElixirAuditAnalyzer. Make sure Elixir and the mix_audit escript is installed. You may also need to set property \"analyzer.mix.audit.path\".");
            Assume.assumeNoException("Exception setting up ElixirMixAuditAnalyzer; mix_audit may not be installed, or property \"analyzer.mix.audit.path\" may not be set.", e);
        }
    }


    /**
     * Test when mix_audit is not available on the system or wrongly configured.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testInvalidMixAuditExecutable() throws AnalysisException, DatabaseException {

        String path = BaseTest.getResourceAsFile(this, "elixir/invalid_executable").getAbsolutePath();
        getSettings().setString(Settings.KEYS.ANALYZER_MIX_AUDIT_PATH, path);
        analyzer.initialize(getSettings());
        try {
            //initialize should fail.
            analyzer.prepare(null);
        } catch (InitializationException e) {
            //expected, so ignore.
            assertNotNull(e);
        } finally {
            assertFalse(analyzer.isEnabled());
        }
    }

    /**
     * Test Mix dependencies and their paths.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     * @throws DatabaseException thrown when an exception occurs
     */
    @Test
    public void testDependenciesPath() throws AnalysisException, DatabaseException {
        try (Engine engine = new Engine(getSettings())) {
            try {
                engine.scan(BaseTest.getResourceAsFile(this, "elixir/mix.lock"));
                engine.analyzeDependencies();
            } catch (NullPointerException ex) {
                LOGGER.error("NPE", ex);
                fail(ex.getMessage());
            } catch (ExceptionCollection ex) {
                Assume.assumeNoException("Exception setting up ElixirMixAuditAnalyzer; mix_audit may not be installed, or property \"analyzer.mix.audit.path\" may not be set.", ex);
                return;
            }
            Dependency[] dependencies = engine.getDependencies();
            LOGGER.info("{} dependencies found.", dependencies.length);
            assertEquals("should find 0 (vulnerable) dependencies", 0, dependencies.length);
        }
    }
}
