package org.owasp.dependencycheck;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestName;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.utils.Settings;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

/**
 * @author Mark Rekveld
 */
public class EngineModeTest extends BaseTest {

    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();
    @Rule
    public TestName testName = new TestName();

    @Before
    public void setUp() throws Exception {
        Settings.setString(Settings.KEYS.DATA_DIRECTORY, tempDir.newFolder().getAbsolutePath());
    }

    @Test
    public void testEvidenceCollectionMode() throws Exception {
        try (Engine engine = new Engine(Engine.Mode.EVIDENCE_COLLECTION)) {
            assertDatabase(false);
            for (AnalysisPhase phase : Engine.Mode.EVIDENCE_COLLECTION.phases) {
                assertThat(engine.getAnalyzers(phase), is(notNullValue()));
            }
            for (AnalysisPhase phase : Engine.Mode.EVIDENCE_PROCESSING.phases) {
                assertThat(engine.getAnalyzers(phase), is(nullValue()));
            }
        }
    }

    @Test
    public void testEvidenceProcessingMode() throws Exception {
        try (Engine engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING)) {
            assertDatabase(true);
            for (AnalysisPhase phase : Engine.Mode.EVIDENCE_PROCESSING.phases) {
                assertThat(engine.getAnalyzers(phase), is(notNullValue()));
            }
            for (AnalysisPhase phase : Engine.Mode.EVIDENCE_COLLECTION.phases) {
                assertThat(engine.getAnalyzers(phase), is(nullValue()));
            }
        }
    }

    @Test
    public void testStandaloneMode() throws Exception {
        try (Engine engine = new Engine(Engine.Mode.STANDALONE)) {
            assertDatabase(true);
            for (AnalysisPhase phase : Engine.Mode.STANDALONE.phases) {
                assertThat(engine.getAnalyzers(phase), is(notNullValue()));
            }
        }
    }

    private void assertDatabase(boolean exists) throws Exception {
        Path directory = Settings.getDataDirectory().toPath();
        assertThat(Files.exists(directory), is(true));
        assertThat(Files.isDirectory(directory), is(true));
        Path database = directory.resolve(Settings.getString(Settings.KEYS.DB_FILE_NAME));
        assertThat(Files.exists(database), is(exists));
    }
}
