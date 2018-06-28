package org.owasp.dependencycheck;

import org.junit.Before;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestName;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Assume;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.FileUtils;

/**
 * @author Mark Rekveld
 */
public class EngineModeIT extends BaseTest {

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();
    @Rule
    public TestName testName = new TestName();

    private String originalDataDir = null;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        // Have to use System properties as the Settings object pulls from the 
        // system properties before configured properties
        originalDataDir = getSettings().getString(Settings.KEYS.DATA_DIRECTORY);
        System.setProperty(Settings.KEYS.DATA_DIRECTORY, tempDir.newFolder().getAbsolutePath());
    }

    @After
    @Override
    public void tearDown() throws Exception {
        try {
            //delete temp files
            FileUtils.delete(getSettings().getDataDirectory());
            //Reset system property to original value just to be safe for other tests.
            System.setProperty(Settings.KEYS.DATA_DIRECTORY, originalDataDir);
            System.clearProperty(Settings.KEYS.H2_DATA_DIRECTORY);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } finally {
            super.tearDown();
        }
    }

    @Test
    public void testEvidenceCollectionAndEvidenceProcessingModes() throws Exception {
        Dependency[] dependencies;
        try (Engine engine = new Engine(Engine.Mode.EVIDENCE_COLLECTION, getSettings())) {
            engine.openDatabase(); //does nothing in the current mode
            assertDatabase(false);
            for (AnalysisPhase phase : Engine.Mode.EVIDENCE_COLLECTION.getPhases()) {
                assertThat(engine.getAnalyzers(phase), is(notNullValue()));
            }
            for (AnalysisPhase phase : Engine.Mode.EVIDENCE_PROCESSING.getPhases()) {
                assertThat(engine.getAnalyzers(phase), is(nullValue()));
            }
            File file = BaseTest.getResourceAsFile(this, "struts2-core-2.1.2.jar");
            engine.scan(file);
            engine.analyzeDependencies();
            dependencies = engine.getDependencies();
            assertThat(dependencies.length, is(1));
            Dependency dependency = dependencies[0];
            assertTrue(dependency.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("apache"));
            assertTrue(dependency.getVendorWeightings().contains("apache"));
            assertTrue(dependency.getVulnerabilities().isEmpty());
        }

        try (Engine engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING, getSettings())) {
            engine.openDatabase();
            assertDatabase(true);
            for (AnalysisPhase phase : Engine.Mode.EVIDENCE_PROCESSING.getPhases()) {
                assertThat(engine.getAnalyzers(phase), is(notNullValue()));
            }
            for (AnalysisPhase phase : Engine.Mode.EVIDENCE_COLLECTION.getPhases()) {
                assertThat(engine.getAnalyzers(phase), is(nullValue()));
            }
            engine.addDependency(dependencies[0]);
            engine.analyzeDependencies();
            Dependency dependency = dependencies[0];
            assertFalse(dependency.getVulnerabilities().isEmpty());
        }
    }

    @Test
    public void testStandaloneMode() throws Exception {
        try (Engine engine = new Engine(Engine.Mode.STANDALONE, getSettings())) {
            engine.openDatabase();
            assertDatabase(true);
            for (AnalysisPhase phase : Engine.Mode.STANDALONE.getPhases()) {
                assertThat(engine.getAnalyzers(phase), is(notNullValue()));
            }
            File file = BaseTest.getResourceAsFile(this, "struts2-core-2.1.2.jar");
            engine.scan(file);
            engine.analyzeDependencies();
            Dependency[] dependencies = engine.getDependencies();
            assertThat(dependencies.length, is(1));
            Dependency dependency = dependencies[0];
            assertTrue(dependency.getEvidence(EvidenceType.VENDOR).toString().toLowerCase().contains("apache"));
            assertTrue(dependency.getVendorWeightings().contains("apache"));
            assertFalse(dependency.getVulnerabilities().isEmpty());
        }
    }

    private void assertDatabase(boolean exists) throws Exception {
        Assume.assumeThat(getSettings().getString(Settings.KEYS.DB_DRIVER_NAME), is("org.h2.Driver"));
        Path directory = getSettings().getDataDirectory().toPath();
        assertThat(Files.exists(directory), is(true));
        assertThat(Files.isDirectory(directory), is(true));
        Path database = directory.resolve(getSettings().getString(Settings.KEYS.DB_FILE_NAME));
        assertThat(Files.exists(database), is(exists));
    }
}
