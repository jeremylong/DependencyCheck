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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.queryparser.classic.ParseException;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.cpe.IndexEntry;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;

/**
 *
 * @author Jeremy Long
 */
public class CPEAnalyzerIntegrationTest extends BaseDBTestCase {

    /**
     * Tests of buildSearch of class CPEAnalyzer.
     *
     * @throws IOException is thrown when an IO Exception occurs.
     * @throws CorruptIndexException is thrown when the index is corrupt.
     * @throws ParseException is thrown when a parse exception occurs
     */
    @Test
    public void testBuildSearch() throws IOException, CorruptIndexException, ParseException {
        Set<String> productWeightings = Collections.singleton("struts2");

        Set<String> vendorWeightings = Collections.singleton("apache");

        String vendor = "apache software foundation";
        String product = "struts 2 core";
        String version = "2.1.2";
        CPEAnalyzer instance = new CPEAnalyzer();

        String queryText = instance.buildSearch(vendor, product, null, null);
        String expResult = " product:( struts 2 core )  AND  vendor:( apache software foundation ) ";
        assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, null, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  AND  vendor:( apache software foundation ) ";
        assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, vendorWeightings, null);
        expResult = " product:( struts 2 core )  AND  vendor:(  apache^5 software foundation ) ";
        assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, vendorWeightings, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  AND  vendor:(  apache^5 software foundation ) ";
        assertTrue(expResult.equals(queryText));
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineCPE_full() throws Exception {
        //update needs to be performed so that xtream can be tested
        Engine e = new Engine();
        e.doUpdates();

        CPEAnalyzer cpeAnalyzer = new CPEAnalyzer();
        try {
            cpeAnalyzer.initialize();
            FileNameAnalyzer fnAnalyzer = new FileNameAnalyzer();
            fnAnalyzer.initialize();
            JarAnalyzer jarAnalyzer = new JarAnalyzer();
            jarAnalyzer.accept(new File("test.jar"));//trick analyzer into "thinking it is active"
            jarAnalyzer.initialize();
            HintAnalyzer hAnalyzer = new HintAnalyzer();
            hAnalyzer.initialize();
            FalsePositiveAnalyzer fp = new FalsePositiveAnalyzer();
            fp.initialize();

            callDetermineCPE_full("hazelcast-2.5.jar", null, cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp);
            callDetermineCPE_full("spring-context-support-2.5.5.jar", "cpe:/a:springsource:spring_framework:2.5.5", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp);
            callDetermineCPE_full("spring-core-3.0.0.RELEASE.jar", "cpe:/a:vmware:springsource_spring_framework:3.0.0", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp);
            callDetermineCPE_full("org.mortbay.jetty.jar", "cpe:/a:mortbay_jetty:jetty:4.2.27", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp);
            callDetermineCPE_full("jaxb-xercesImpl-1.5.jar", null, cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp);
            callDetermineCPE_full("ehcache-core-2.2.0.jar", null, cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp);
            callDetermineCPE_full("xstream-1.4.8.jar", "cpe:/a:x-stream:xstream:1.4.8", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp);

        } finally {
            cpeAnalyzer.close();
        }
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    public void callDetermineCPE_full(String depName, String expResult, CPEAnalyzer cpeAnalyzer, FileNameAnalyzer fnAnalyzer, JarAnalyzer jarAnalyzer, HintAnalyzer hAnalyzer, FalsePositiveAnalyzer fp) throws Exception {

        //File file = new File(this.getClass().getClassLoader().getResource(depName).getPath());
        File file = BaseTest.getResourceAsFile(this, depName);

        Dependency dep = new Dependency(file);

        fnAnalyzer.analyze(dep, null);
        jarAnalyzer.analyze(dep, null);
        hAnalyzer.analyze(dep, null);
        cpeAnalyzer.analyze(dep, null);
        fp.analyze(dep, null);

        if (expResult != null) {
            Identifier expIdentifier = new Identifier("cpe", expResult, expResult);
            assertTrue("Incorrect match: { dep:'" + dep.getFileName() + "' }", dep.getIdentifiers().contains(expIdentifier));
        } else {
            for (Identifier i : dep.getIdentifiers()) {
                assertFalse(String.format("%s - found a CPE identifier when should have been none (found '%s')", dep.getFileName(), i.getValue()), "cpe".equals(i.getType()));
            }
        }
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineCPE() throws Exception {
        //File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        File file = BaseTest.getResourceAsFile(this, "struts2-core-2.1.2.jar");
        //File file = new File(this.getClass().getClassLoader().getResource("axis2-adb-1.4.1.jar").getPath());
        Dependency struts = new Dependency(file);

        FileNameAnalyzer fnAnalyzer = new FileNameAnalyzer();
        fnAnalyzer.analyze(struts, null);

        HintAnalyzer hintAnalyzer = new HintAnalyzer();
        hintAnalyzer.initialize();
        JarAnalyzer jarAnalyzer = new JarAnalyzer();
        jarAnalyzer.accept(new File("test.jar"));//trick analyzer into "thinking it is active"
        jarAnalyzer.initialize();

        jarAnalyzer.analyze(struts, null);
        hintAnalyzer.analyze(struts, null);
        //File fileCommonValidator = new File(this.getClass().getClassLoader().getResource("commons-validator-1.4.0.jar").getPath());
        File fileCommonValidator = BaseTest.getResourceAsFile(this, "commons-validator-1.4.0.jar");
        Dependency commonValidator = new Dependency(fileCommonValidator);
        jarAnalyzer.analyze(commonValidator, null);
        hintAnalyzer.analyze(commonValidator, null);

        //File fileSpring = new File(this.getClass().getClassLoader().getResource("spring-core-2.5.5.jar").getPath());
        File fileSpring = BaseTest.getResourceAsFile(this, "spring-core-2.5.5.jar");
        Dependency spring = new Dependency(fileSpring);
        jarAnalyzer.analyze(spring, null);
        hintAnalyzer.analyze(spring, null);

        //File fileSpring3 = new File(this.getClass().getClassLoader().getResource("spring-core-3.0.0.RELEASE.jar").getPath());
        File fileSpring3 = BaseTest.getResourceAsFile(this, "spring-core-3.0.0.RELEASE.jar");
        Dependency spring3 = new Dependency(fileSpring3);
        jarAnalyzer.analyze(spring3, null);
        hintAnalyzer.analyze(spring3, null);

        CPEAnalyzer instance = new CPEAnalyzer();
        instance.open();
        instance.determineCPE(commonValidator);
        instance.determineCPE(struts);
        instance.determineCPE(spring);
        instance.determineCPE(spring3);
        instance.close();

        String expResult = "cpe:/a:apache:struts:2.1.2";
        Identifier expIdentifier = new Identifier("cpe", expResult, expResult);

        for (Identifier i : commonValidator.getIdentifiers()) {
            assertFalse("Apache Common Validator - found a CPE identifier?", "cpe".equals(i.getType()));
        }

        assertTrue("Incorrect match size - struts", struts.getIdentifiers().size() >= 1);
        assertTrue("Incorrect match - struts", struts.getIdentifiers().contains(expIdentifier));
        assertTrue("Incorrect match size - spring3 - " + spring3.getIdentifiers().size(), spring3.getIdentifiers().size() >= 1);

        jarAnalyzer.close();
    }

    /**
     * Test of determineIdentifiers method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineIdentifiers() throws Exception {
        Dependency openssl = new Dependency();
        openssl.getVendorEvidence().addEvidence("test", "vendor", "openssl", Confidence.HIGHEST);
        openssl.getProductEvidence().addEvidence("test", "product", "openssl", Confidence.HIGHEST);
        openssl.getVersionEvidence().addEvidence("test", "version", "1.0.1c", Confidence.HIGHEST);

        CPEAnalyzer instance = new CPEAnalyzer();
        instance.open();
        instance.determineIdentifiers(openssl, "openssl", "openssl", Confidence.HIGHEST);
        instance.close();

        String expResult = "cpe:/a:openssl:openssl:1.0.1c";
        Identifier expIdentifier = new Identifier("cpe", expResult, expResult);

        assertTrue(openssl.getIdentifiers().contains(expIdentifier));

    }

    /**
     * Test of searchCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testSearchCPE() throws Exception {
        String vendor = "apache software foundation";
        String product = "struts 2 core";
        String expVendor = "apache";
        String expProduct = "struts";

        CPEAnalyzer instance = new CPEAnalyzer();
        instance.open();

        Set<String> productWeightings = Collections.singleton("struts2");
        Set<String> vendorWeightings = Collections.singleton("apache");
        List<IndexEntry> result = instance.searchCPE(vendor, product, vendorWeightings, productWeightings);
        instance.close();

        boolean found = false;
        for (IndexEntry entry : result) {
            if (expVendor.equals(entry.getVendor()) && expProduct.equals(entry.getProduct())) {
                found = true;
                break;
            }
        }
        assertTrue("apache:struts was not identified", found);
    }
}
