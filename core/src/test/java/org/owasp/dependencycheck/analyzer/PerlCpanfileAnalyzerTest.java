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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.mutable.MutableInt;
import org.junit.Test;
import static org.junit.Assert.*;

import mockit.Expectations;
import mockit.Mocked;
import mockit.Verifications;

import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.ICveDBWrapper;
import org.owasp.dependencycheck.data.nvdcve.CveDBWrapper;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.Engine.Mode;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.models.VulnerabilityDTO;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author jeremy long
 */
public class PerlCpanfileAnalyzerTest extends BaseTest {
    public class FakeCveDBWrapper implements ICveDBWrapper {
        private Vulnerability fakeVulnerability;
        private List<VulnerabilityDTO> fakeVulnerabilities;
    
        public FakeCveDBWrapper(){
            this.fakeVulnerabilities = new ArrayList<VulnerabilityDTO>();
            this.fakeVulnerabilities.add(new VulnerabilityDTO(1, "Fake Software House Ltd", "Calculator", "0.0.1", "0.1", "CVE001"));
            this.fakeVulnerabilities.add(new VulnerabilityDTO(1, "ORG", "ORG::OWASP::DEPENDENCYCHECK", "0.1", "0.2", "CVE001"));
            this.fakeVulnerabilities.add(new VulnerabilityDTO(2, "ORG", "ORG::OWASP::DEPENDENCYCHECK", "0.1", "0.2", "CVE002"));
        }
        public Vulnerability getVulnerability(String reference){
            return new Vulnerability(reference);
        }
        public List<VulnerabilityDTO> getPerlVulnerabilities(){
            return this.fakeVulnerabilities;
        }
    }

    /**
     * Test of getName method, of class PerlCpanfileAnalyzer.
     */
    @Test
    public void testGetName() {
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        String expResult = "Perl cpanfile Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class PerlCpanfileAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.INFORMATION_COLLECTION;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class PerlCpanfileAnalyzer.
     */
    @Test
    public void testGetAnalyzerEnabledSettingKey() {
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    /**
     * Test of collectTerms method, of class PerlCpanfileAnalyzer.
     */
    @Test
    public void testAnalyzeDependencyWhenDependencyListIsEmpty() throws AnalysisException{
        Dependency d = new Dependency();
        List<VulnerabilityDTO> vulnerabileProductList =  new ArrayList<>();
        String[] dependencyLines = {
            "requires 'Mojolicious::Plugin::ZAPI' => '>= 2.015", 
            "requires 'Hash::MoreUtils' => '>= 0.05", 
            "requires 'JSON::MaybeXS' => '>= 1.002004'; # is_bool", 
            "# requires 'JSON::MaybeXS' => '>= 1.002004';",
            "comment about something",
            "requires 'Test::MockModule';"
        };
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer(vulnerabileProductList, new FakeCveDBWrapper());
        instance.processFileContents(dependencyLines, d);
        assertEquals(d.getVulnerabilities().size(), 0);
    }

    /**
     * Test of collectTerms method, of class PerlCpanfileAnalyzer.
     */
    @Test
    public void testAnalyzeDependencyWhenDependencyListHasNoMatchingDependencies() throws AnalysisException{
        Dependency d = new Dependency();
        List<VulnerabilityDTO> vulnerabileProductList =  new ArrayList<>();
        vulnerabileProductList.add(new VulnerabilityDTO(1, "Fake Software House Ltd", "Calculator", "0.0.1", "0.1", "CVE001"));
        String[] dependencyLines = {
            "requires 'ORG::OWASP::DEPENDENCYCHECK' => '>= 0.05"
        };
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer(vulnerabileProductList, new FakeCveDBWrapper());
        instance.processFileContents(dependencyLines, d);
        assertEquals(d.getVulnerabilities().size(), 0);
    }

    /**
     * Test of collectTerms method, of class PerlCpanfileAnalyzer.
     */
    @Test
    public void testAnalyzeDependencyWhenDependencyListHasOneMatchingDependency() throws AnalysisException{
        Dependency d = new Dependency();
        List<VulnerabilityDTO> vulnerabileProductList =  new ArrayList<>();
        vulnerabileProductList.add(new VulnerabilityDTO(1, "ORG", "ORG::OWASP::DEPENDENCYCHECK", "0.1", "0.2", "CVE001"));
        String[] dependencyLines = {
            "requires 'ORG::OWASP::DEPENDENCYCHECK' => '>= 0.05"
        };
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer(vulnerabileProductList, new FakeCveDBWrapper());
        instance.processFileContents(dependencyLines, d);
        assertEquals(d.getVulnerabilities().size(), 1);
    }

    /**
     * Test of collectTerms method, of class PerlCpanfileAnalyzer.
     */
    @Test
    public void testAnalyzeDependencyWhenDependencyListHasTwoMatchingDependency() throws AnalysisException{
        Dependency d = new Dependency();
        List<VulnerabilityDTO> vulnerabileProductList =  new ArrayList<>();
        vulnerabileProductList.add(new VulnerabilityDTO(1, "ORG", "ORG::OWASP::DEPENDENCYCHECK", "0.1", "0.2", "CVE001"));
        vulnerabileProductList.add(new VulnerabilityDTO(2, "ORG", "ORG::OWASP::DEPENDENCYCHECK", "0.1", "0.2", "CVE002"));
        String[] dependencyLines = {
            "requires 'ORG::OWASP::DEPENDENCYCHECK' => '>= 0.05"
        };
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer(vulnerabileProductList, new FakeCveDBWrapper());
        instance.processFileContents(dependencyLines, d);
        assertEquals(d.getVulnerabilities().size(), 2);
    }

    /**
     * Test of collectTerms method, of class PerlCpanfileAnalyzer.
     */
    @Test
    public void testAnalyzeDependencyWhenDependencyListHasTwogDependenciesButFileContainsNone() throws AnalysisException{
        Dependency d = new Dependency();
        List<VulnerabilityDTO> vulnerabileProductList =  new ArrayList<>();
        vulnerabileProductList.add(new VulnerabilityDTO(1, "ORG", "ORG::OWASP::DEPENDENCYCHECK", "0.1", "0.2", "CVE001"));
        vulnerabileProductList.add(new VulnerabilityDTO(2, "ORG", "ORG::OWASP::DEPENDENCYCHECK", "0.1", "0.2", "CVE002"));
        String[] dependencyLines = {
        };
        PerlCpanfileAnalyzer instance = new PerlCpanfileAnalyzer(vulnerabileProductList, new FakeCveDBWrapper());
        instance.processFileContents(dependencyLines, d);
        assertEquals(d.getVulnerabilities().size(), 0);
    }
}
