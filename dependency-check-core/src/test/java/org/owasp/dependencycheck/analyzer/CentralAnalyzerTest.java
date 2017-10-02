package org.owasp.dependencycheck.analyzer;

import mockit.Expectations;
import mockit.Mock;
import mockit.MockUp;
import mockit.Mocked;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.data.central.CentralSearch;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * Tests for the CentralAnalyzer.
 */
public class CentralAnalyzerTest {

    private static final String SHA1_SUM = "my-sha1-sum";

    @BeforeClass
    public static void beforeClass() {
        doNotSleepBetweenRetries();
    }

    @Test
    public void testFetchMavenArtifactsWithoutException(@Mocked final CentralSearch centralSearch,
                                                        @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.searcher = centralSearch;

        final List<MavenArtifact> expectedMavenArtifacts = Collections.emptyList();
        new Expectations() {{
            dependency.getSha1sum();
            returns(SHA1_SUM);

            centralSearch.searchSha1(SHA1_SUM);
            returns(expectedMavenArtifacts);
        }};

        final List<MavenArtifact> actualMavenArtifacts = instance.fetchMavenArtifacts(dependency);

        assertEquals(expectedMavenArtifacts, actualMavenArtifacts);
    }

    @Test
    public void testFetchMavenArtifactsWithSporadicIOException(@Mocked final CentralSearch centralSearch,
                                                               @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.searcher = centralSearch;

        final List<MavenArtifact> expectedMavenArtifacts = Collections.emptyList();
        new Expectations() {{
            dependency.getSha1sum();
            returns(SHA1_SUM);

            centralSearch.searchSha1(SHA1_SUM);
            result = new IOException("Could not connect to MavenCentral (500): Internal Server Error");
            result = new IOException("Could not connect to MavenCentral (500): Internal Server Error");
            result = expectedMavenArtifacts;
        }};

        final List<MavenArtifact> actualMavenArtifacts = instance.fetchMavenArtifacts(dependency);

        assertEquals(expectedMavenArtifacts, actualMavenArtifacts);
    }

    @Test(expected = FileNotFoundException.class)
    public void testFetchMavenArtifactsRethrowsFileNotFoundException(@Mocked final CentralSearch centralSearch,
                                                                     @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.searcher = centralSearch;

        new Expectations() {{
            dependency.getSha1sum();
            returns(SHA1_SUM);

            centralSearch.searchSha1(SHA1_SUM);
            result = new FileNotFoundException("Artifact not found in Central");
        }};

        instance.fetchMavenArtifacts(dependency);
    }

    @Test(expected = IOException.class)
    public void testFetchMavenArtifactsAlwaysThrowsIOException(@Mocked final CentralSearch centralSearch,
                                                               @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.searcher = centralSearch;

        new Expectations() {{
            dependency.getSha1sum();
            returns(SHA1_SUM);

            centralSearch.searchSha1(SHA1_SUM);
            result = new IOException("no internet connection");
        }};

        instance.fetchMavenArtifacts(dependency);
    }

    /**
     * We do not want to waste time in unit tests.
     */
    private static void doNotSleepBetweenRetries() {
        new MockUp<Thread>() {
            @Mock
            void sleep(long millis) {
                // do not sleep
            }
        };
    }
}
