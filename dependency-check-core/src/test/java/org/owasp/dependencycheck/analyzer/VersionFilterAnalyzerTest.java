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

import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author jerem
 */
public class VersionFilterAnalyzerTest extends BaseTest {

    /**
     * Test of getName method, of class VersionFilterAnalyzer.
     */
    @Test
    public void testGetName() {
        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        String expResult = "Version Filter Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class VersionFilterAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.POST_INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class
     * VersionFilterAnalyzer.
     */
    @Test
    public void testGetAnalyzerEnabledSettingKey() {
        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_VERSION_FILTER_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyzeDependency method, of class VersionFilterAnalyzer.
     */
    @Test
    public void testAnalyzeDependency() throws Exception {
        Dependency dependency = new Dependency();
        EvidenceCollection versions = dependency.getVersionEvidence();

        versions.addEvidence("util", "version", "33.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        versions.addEvidence("other", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();

        instance.analyzeDependency(dependency, null);
        assertEquals(3, versions.size());

        versions.addEvidence("pom", "version", "1.2.3", Confidence.HIGHEST);

        instance.analyzeDependency(dependency, null);
        assertEquals(4, versions.size());

        versions.addEvidence("file", "version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(2, versions.size());

        versions.addEvidence("Manifest", "Implementation-Version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(3, versions.size());

        versions.addEvidence("nexus", "version", "1.2.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(4, versions.size());

        versions.addEvidence("central", "version", "1.2.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(5, versions.size());
    }

    /**
     * Test of analyzeDependency method, of class VersionFilterAnalyzer.
     */
    @Test
    public void testAnalyzeDependencyFilePom() throws Exception {
        Dependency dependency = new Dependency();
        EvidenceCollection versions = dependency.getVersionEvidence();

        versions.addEvidence("util", "version", "33.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        versions.addEvidence("other", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();

        instance.analyzeDependency(dependency, null);
        assertEquals(3, versions.size());

        versions.addEvidence("pom", "version", "1.2.3", Confidence.HIGHEST);

        instance.analyzeDependency(dependency, null);
        assertEquals(4, versions.size());

        versions.addEvidence("file", "version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(2, versions.size());

        versions.addEvidence("nexus", "version", "1.2.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(3, versions.size());

        versions.addEvidence("central", "version", "1.2.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(4, versions.size());
    }

    /**
     * Test of analyzeDependency method, of class VersionFilterAnalyzer.
     */
    @Test
    public void testAnalyzeDependencyFileManifest() throws Exception {
        Dependency dependency = new Dependency();
        EvidenceCollection versions = dependency.getVersionEvidence();

        versions.addEvidence("util", "version", "33.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        versions.addEvidence("other", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();

        instance.analyzeDependency(dependency, null);
        assertEquals(3, versions.size());

        versions.addEvidence("Manifest", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        instance.analyzeDependency(dependency, null);
        assertEquals(4, versions.size());

        versions.addEvidence("file", "version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(2, versions.size());
    }

    /**
     * Test of analyzeDependency method, of class VersionFilterAnalyzer.
     */
    @Test
    public void testAnalyzeDependencyPomManifest() throws Exception {
        Dependency dependency = new Dependency();
        EvidenceCollection versions = dependency.getVersionEvidence();

        versions.addEvidence("util", "version", "33.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        versions.addEvidence("other", "Implementation-Version", "1.2.3", Confidence.HIGHEST);

        VersionFilterAnalyzer instance = new VersionFilterAnalyzer();

        instance.analyzeDependency(dependency, null);
        assertEquals(3, versions.size());

        versions.addEvidence("pom", "version", "1.2.3", Confidence.HIGHEST);

        instance.analyzeDependency(dependency, null);
        assertEquals(4, versions.size());

        versions.addEvidence("Manifest", "Implementation-Version", "1.2.3", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(2, versions.size());

        versions.addEvidence("nexus", "version", "1.2.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(3, versions.size());

        versions.addEvidence("central", "version", "1.2.3", Confidence.HIGHEST);
        versions.addEvidence("other", "version", "alpha", Confidence.HIGHEST);
        instance.analyzeDependency(dependency, null);
        assertEquals(4, versions.size());
    }

}
