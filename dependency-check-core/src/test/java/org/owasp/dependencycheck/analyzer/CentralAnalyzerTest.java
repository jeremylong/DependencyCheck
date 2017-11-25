/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import mockit.Expectations;
import mockit.Mock;
import mockit.MockUp;
import mockit.Mocked;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
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
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsWithoutException(@Mocked final CentralSearch centralSearch,
            @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        specifySha1SumFor(dependency);

        final List<MavenArtifact> expectedMavenArtifacts = Collections.emptyList();
        new Expectations() {
            {
                centralSearch.searchSha1(SHA1_SUM);
                returns(expectedMavenArtifacts);
            }
        };

        final List<MavenArtifact> actualMavenArtifacts = instance.fetchMavenArtifacts(dependency);

        assertEquals(expectedMavenArtifacts, actualMavenArtifacts);
    }

    @Test
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsWithSporadicIOException(@Mocked final CentralSearch centralSearch,
            @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        specifySha1SumFor(dependency);

        final List<MavenArtifact> expectedMavenArtifacts = Collections.emptyList();
        new Expectations() {
            {
                centralSearch.searchSha1(SHA1_SUM);
                //result = new IOException("Could not connect to MavenCentral (500): Internal Server Error");
                result = expectedMavenArtifacts;
            }
        };

        final List<MavenArtifact> actualMavenArtifacts = instance.fetchMavenArtifacts(dependency);

        assertEquals(expectedMavenArtifacts, actualMavenArtifacts);
    }

    @Test(expected = FileNotFoundException.class)
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsRethrowsFileNotFoundException(@Mocked final CentralSearch centralSearch,
            @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        specifySha1SumFor(dependency);

        new Expectations() {
            {
                centralSearch.searchSha1(SHA1_SUM);
                result = new FileNotFoundException("Artifact not found in Central");
            }
        };

        instance.fetchMavenArtifacts(dependency);
    }

    @Test(expected = IOException.class)
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsAlwaysThrowsIOException(@Mocked final CentralSearch centralSearch,
            @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        specifySha1SumFor(dependency);

        new Expectations() {
            {
                centralSearch.searchSha1(SHA1_SUM);
                result = new IOException("no internet connection");
            }
        };

        instance.fetchMavenArtifacts(dependency);
    }

    @Test(expected = AnalysisException.class)
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsAlwaysThrowsIOExceptionLetsTheAnalysisFail(
            @Mocked final CentralSearch centralSearch, @Mocked final Dependency dependency)
            throws AnalysisException, IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        specifySha1SumFor(dependency);

        new Expectations() {
            {
                centralSearch.searchSha1(SHA1_SUM);
                result = new IOException("no internet connection");
            }
        };

        instance.analyze(dependency, null);
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

    /**
     * Specifies the mock dependency's SHA1 sum.
     *
     * @param dependency then dependency
     */
    @SuppressWarnings("PMD.NonStaticInitializer")
    private void specifySha1SumFor(final Dependency dependency) {
        new Expectations() {
            {
                dependency.getSha1sum();
                returns(SHA1_SUM);
            }
        };
    }
}
