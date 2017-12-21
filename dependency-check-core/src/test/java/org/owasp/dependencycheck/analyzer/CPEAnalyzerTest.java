/*
 * Copyright 2017 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.cpe.IndexEntry;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author jeremy
 */
public class CPEAnalyzerTest {

    /**
     * Test of getName method, of class CPEAnalyzer.
     */
    @Test
    public void testGetName() {
        CPEAnalyzer instance = new CPEAnalyzer();
        String expResult = "CPE Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class CPEAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        CPEAnalyzer instance = new CPEAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.IDENTIFIER_ANALYSIS;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalyzerEnabledSettingKey method, of class CPEAnalyzer.
     */
    @Test
    public void testGetAnalyzerEnabledSettingKey() {
        CPEAnalyzer instance = new CPEAnalyzer();
        String expResult = Settings.KEYS.ANALYZER_CPE_ENABLED;
        String result = instance.getAnalyzerEnabledSettingKey();
        assertEquals(expResult, result);
    }

    /**
     * Test of addEvidenceWithoutDuplicateTerms method, of class CPEAnalyzer.
     */
    @Test
    public void testAddEvidenceWithoutDuplicateTerms() {
        String text = "";
        List<Evidence> evidence = new ArrayList<>();
        evidence.add(new Evidence("test case", "value", "test", Confidence.HIGHEST));
        CPEAnalyzer instance = new CPEAnalyzer();
        String expResult = "test";
        String result = instance.addEvidenceWithoutDuplicateTerms(text, evidence);
        assertEquals(expResult, result);
        
        text = "some";
        expResult = "some test";
        result = instance.addEvidenceWithoutDuplicateTerms(text, evidence);
        assertEquals(expResult, result);
        
        text = "test";
        expResult = "test";
        result = instance.addEvidenceWithoutDuplicateTerms(text, evidence);
        assertEquals(expResult, result);
        
        
        StringBuilder sb = new  StringBuilder();
        StringBuilder expect = new StringBuilder();
        for (int x=0;x<500;x++) {
            sb.append("items ");
            if (expect.length()+5<1000) {
                expect.append("items ");
            }
        }
        evidence.clear();
        evidence.add(new Evidence("test case", "value", sb.toString(), Confidence.HIGHEST));
        text = "";
        expResult = expect.toString().trim();
        result = instance.addEvidenceWithoutDuplicateTerms(text, evidence);
        assertEquals(expResult, result);
    }

    /**
     * Test of buildSearch method, of class CPEAnalyzer.
     */
    @Test
    public void testBuildSearch() {
        String vendor = "apache software foundation";
        String product = "lucene index";
        Set<String> vendorWeighting = null;
        Set<String> productWeightings = null;
        
        CPEAnalyzer instance = new CPEAnalyzer();
        String expResult = "product:(lucene index) AND vendor:(apache software foundation)";
        String result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);
        
        vendorWeighting = new HashSet<>();
        productWeightings = new HashSet<>();
        expResult = "product:(lucene index) AND vendor:(apache software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);
        
        vendorWeighting.add("apache");
        expResult = "product:(lucene index) AND vendor:(apache^5 software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);
        
        productWeightings.add("lucene");
        expResult = "product:(lucene^5 index) AND vendor:(apache^5 software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);
        
        productWeightings.add("ignored");
        expResult = "product:(lucene^5 index) AND vendor:(apache^5 software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);
        
        vendorWeighting.clear();
        expResult = "product:(lucene^5 index) AND vendor:(apache software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);
        
        vendorWeighting.add("ignored");
        productWeightings.clear();
        expResult = "product:(lucene index) AND vendor:(apache software foundation)";
        result = instance.buildSearch(vendor, product, vendorWeighting, productWeightings);
        assertEquals(expResult, result);
    }

    /**
     * Test of prepareAnalyzer method, of class CPEAnalyzer.
     */
    @Test
    public void testPrepareAnalyzer() throws Exception {
        //Part of the integration tests.
    }

    /**
     * Test of open method, of class CPEAnalyzer.
     */
    @Test
    public void testOpen() throws Exception {
        //Part of the integration tests.
    }

    /**
     * Test of closeAnalyzer method, of class CPEAnalyzer.
     */
    @Test
    public void testCloseAnalyzer() {
        //Part of the integration tests.
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     */
    @Test
    public void testDetermineCPE() throws Exception {
        //Part of the integration tests.
    }

    /**
     * Test of searchCPE method, of class CPEAnalyzer.
     */
    @Test
    public void testSearchCPE() {
        //Part of the integration tests.
    }

    /**
     * Test of analyzeDependency method, of class CPEAnalyzer.
     */
    @Test
    public void testAnalyzeDependency() throws Exception {
        //Part of the integration tests.
    }

    /**
     * Test of determineIdentifiers method, of class CPEAnalyzer.
     */
    @Test
    public void testDetermineIdentifiers() throws Exception {
        //Part of the integration tests.
    }
}
