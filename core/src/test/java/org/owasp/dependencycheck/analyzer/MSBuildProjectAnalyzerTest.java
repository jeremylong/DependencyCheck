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
 * Copyright (c) 2018 Paul Irwin. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;

import java.io.File;
import java.util.stream.Collectors;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.owasp.dependencycheck.analyzer.NuspecAnalyzer.DEPENDENCY_ECOSYSTEM;

public class MSBuildProjectAnalyzerTest extends BaseTest {

    private MSBuildProjectAnalyzer instance;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        instance = new MSBuildProjectAnalyzer();
        instance.initialize(getSettings());
        instance.prepare(null);
        instance.setEnabled(true);

    }

    @Test
    public void testGetAnalyzerName() {
        assertEquals("MSBuild Project Analyzer", instance.getName());
    }

    @Test
    public void testSupportsFileExtensions() {
        assertTrue(instance.accept(new File("test.csproj")));
        assertTrue(instance.accept(new File("test.vbproj")));
        assertFalse(instance.accept(new File("test.nuspec")));
    }

    @Test
    public void testGetAnalysisPhaze() {
        assertEquals(AnalysisPhase.INFORMATION_COLLECTION, instance.getAnalysisPhase());
    }

    @Test
    public void testMSBuildProjectAnalysis() throws Exception {

        try (Engine engine = new Engine(getSettings())) {
            File file = BaseTest.getResourceAsFile(this, "msbuild/test.csproj");
            Dependency toScan = new Dependency(file);
            MSBuildProjectAnalyzer analyzer = new MSBuildProjectAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            analyzer.setEnabled(true);
            analyzer.analyze(toScan, engine);

            assertEquals("5 dependencies should be found", 5, engine.getDependencies().length);

            int foundCount = 0;

            for (Dependency result : engine.getDependencies()) {
                assertEquals(DEPENDENCY_ECOSYSTEM, result.getEcosystem());
                assertTrue(result.isVirtual());

                if (null != result.getName()) {
                    switch (result.getName()) {
                        case "Humanizer":
                            foundCount++;
                            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("Humanizer"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Humanizer"));
                            assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("2.2.0"));
                            break;
                        case "JetBrains.Annotations":
                            foundCount++;
                            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("JetBrains"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("JetBrains.Annotations"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Annotations"));
                            assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("11.1.0"));
                            break;
                        case "Microsoft.AspNetCore.All":
                            foundCount++;
                            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("Microsoft"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Microsoft.AspNetCore.All"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("AspNetCore"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("AspNetCore.All"));
                            assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("2.0.5"));
                            break;
                        case "Microsoft.Extensions.Logging":
                            foundCount++;
                            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("Microsoft"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Microsoft.Extensions.Logging"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Extensions"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Extensions.Logging"));
                            assertTrue(result.getEvidence(EvidenceType.VERSION).toString().contains("6.0.0"));
                            break;
                        case "NodaTime":
                            foundCount++;
                            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("NodaTime"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("NodaTime"));
                            assertTrue("Expected 3.0.0; contained: " + result.getEvidence(EvidenceType.VERSION).stream().map(e -> e.toString()).collect(Collectors.joining(",", "{", "}")), result.getEvidence(EvidenceType.VERSION).toString().contains("3.0.0"));
                            break;
                        default:
                            break;
                    }
                }
            }

            assertEquals("5 expected dependencies should be found", 5, foundCount);
        }
    }

    @Test
    public void testMSBuildProjectAnalysis_WithImports() throws Exception {
        testMSBuildProjectAnalysisWithImport("msbuild/ProjectA/ProjectA.csproj", "3.0.0", "1.0.0");
        testMSBuildProjectAnalysisWithImport("msbuild/ProjectB/ProjectB.csproj", "3.0.0", "2.0.0");
        testMSBuildProjectAnalysisWithImport("msbuild/ProjectC/ProjectC.csproj", "3.0.0", "3.0.0");
        testMSBuildProjectAnalysisWithImport("msbuild/ProjectD/ProjectD.csproj", "4.0.0", "4.0.0");
        testMSBuildProjectAnalysisWithImport("msbuild/ProjectE/ProjectE.csproj", "3.0.0", "5.0.0");
        testMSBuildProjectAnalysisWithImport("msbuild/ProjectF/ProjectF.csproj", "5.1.0", "6.1.0");
    }

    public void testMSBuildProjectAnalysisWithImport(String path, String nodaVersion, String humanizerVersion) throws Exception {

        try (Engine engine = new Engine(getSettings())) {
            File file = BaseTest.getResourceAsFile(this, path);
            Dependency toScan = new Dependency(file);
            MSBuildProjectAnalyzer analyzer = new MSBuildProjectAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize(getSettings());
            analyzer.prepare(engine);
            analyzer.setEnabled(true);
            analyzer.analyze(toScan, engine);

            assertEquals("2 dependencies should be found", 2, engine.getDependencies().length);

            int foundCount = 0;

            for (Dependency result : engine.getDependencies()) {
                assertEquals(DEPENDENCY_ECOSYSTEM, result.getEcosystem());
                assertTrue(result.isVirtual());

                if (null != result.getName()) {
                    switch (result.getName()) {
                        case "Humanizer":
                            foundCount++;
                            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("Humanizer"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("Humanizer"));
                            assertTrue("Expected " + humanizerVersion + "; contained: " + result.getEvidence(EvidenceType.VERSION).stream().map(e -> e.toString()).collect(Collectors.joining(",", "{", "}")), result.getEvidence(EvidenceType.VERSION).toString().contains(humanizerVersion));
                            break;
                        case "NodaTime":
                            foundCount++;
                            assertTrue(result.getEvidence(EvidenceType.VENDOR).toString().contains("NodaTime"));
                            assertTrue(result.getEvidence(EvidenceType.PRODUCT).toString().contains("NodaTime"));
                            assertTrue("Expected " + nodaVersion + "; contained: " + result.getEvidence(EvidenceType.VERSION).stream().map(e -> e.toString()).collect(Collectors.joining(",", "{", "}")), result.getEvidence(EvidenceType.VERSION).toString().contains(nodaVersion));
                            break;
                        default:
                            break;
                    }
                }
            }

            assertEquals("2 expected dependencies should be found", 2, foundCount);
        }
    }
}
