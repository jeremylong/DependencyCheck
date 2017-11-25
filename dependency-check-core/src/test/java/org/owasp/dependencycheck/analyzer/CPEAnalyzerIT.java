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
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.cpe.IndexEntry;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.owasp.dependencycheck.dependency.EvidenceType;

/**
 *
 * @author Jeremy Long
 */
public class CPEAnalyzerIT extends BaseDBTestCase {

    /**
     * Tests of buildSearch of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an IO Exception occurs.
     */
    @Test
    public void testBuildSearch() throws Exception {
        Set<String> productWeightings = Collections.singleton("struts2");

        Set<String> vendorWeightings = Collections.singleton("apache");

        String vendor = "apache software foundation";
        String product = "struts 2 core";

        CPEAnalyzer instance = new CPEAnalyzer();
        instance.initialize(getSettings());
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
        instance.close();
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineCPE_full() throws Exception {
        CPEAnalyzer cpeAnalyzer = new CPEAnalyzer();
        try (Engine e = new Engine(getSettings())) {
            //update needs to be performed so that xtream can be tested
            e.doUpdates(true);
            cpeAnalyzer.initialize(getSettings());
            cpeAnalyzer.prepare(e);
            FileNameAnalyzer fnAnalyzer = new FileNameAnalyzer();
            fnAnalyzer.initialize(getSettings());
            fnAnalyzer.prepare(e);
            JarAnalyzer jarAnalyzer = new JarAnalyzer();
            jarAnalyzer.initialize(getSettings());
            jarAnalyzer.accept(new File("test.jar"));//trick analyzer into "thinking it is active"
            jarAnalyzer.prepare(e);
            HintAnalyzer hAnalyzer = new HintAnalyzer();
            hAnalyzer.initialize(getSettings());
            hAnalyzer.prepare(e);
            FalsePositiveAnalyzer fp = new FalsePositiveAnalyzer();
            fp.initialize(getSettings());
            fp.prepare(e);

            CpeSuppressionAnalyzer cpeSuppression = new CpeSuppressionAnalyzer();
            cpeSuppression.initialize(getSettings());
            cpeSuppression.prepare(e);

            callDetermineCPE_full("hazelcast-2.5.jar", null, cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("spring-context-support-2.5.5.jar", "cpe:/a:springsource:spring_framework:2.5.5", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("spring-core-3.0.0.RELEASE.jar", "cpe:/a:vmware:springsource_spring_framework:3.0.0", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("jaxb-xercesImpl-1.5.jar", null, cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("ehcache-core-2.2.0.jar", null, cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("org.mortbay.jetty.jar", "cpe:/a:mortbay_jetty:jetty:4.2.27", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
            callDetermineCPE_full("xstream-1.4.8.jar", "cpe:/a:x-stream:xstream:1.4.8", cpeAnalyzer, fnAnalyzer, jarAnalyzer, hAnalyzer, fp, cpeSuppression);
        } finally {
            cpeAnalyzer.close();
        }
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    public void callDetermineCPE_full(String depName, String expResult, CPEAnalyzer cpeAnalyzer, FileNameAnalyzer fnAnalyzer,
            JarAnalyzer jarAnalyzer, HintAnalyzer hAnalyzer, FalsePositiveAnalyzer fp, CpeSuppressionAnalyzer cpeSuppression) throws Exception {

        //File file = new File(this.getClass().getClassLoader().getResource(depName).getPath());
        File file = BaseTest.getResourceAsFile(this, depName);

        Dependency dep = new Dependency(file);

        fnAnalyzer.analyze(dep, null);
        jarAnalyzer.analyze(dep, null);
        hAnalyzer.analyze(dep, null);
        cpeAnalyzer.analyze(dep, null);
        fp.analyze(dep, null);
        cpeSuppression.analyze(dep, null);

        if (expResult != null) {
            boolean found = false;
            for (Identifier i : dep.getIdentifiers()) {
                if (expResult.equals(i.getValue())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Incorrect match: { dep:'" + dep.getFileName() + "' }", found);
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
        hintAnalyzer.initialize(getSettings());
        hintAnalyzer.prepare(null);
        JarAnalyzer jarAnalyzer = new JarAnalyzer();
        jarAnalyzer.initialize(getSettings());
        jarAnalyzer.accept(new File("test.jar"));//trick analyzer into "thinking it is active"
        jarAnalyzer.prepare(null);

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
        try (Engine engine = new Engine(getSettings())) {
            engine.openDatabase(true, true);
            instance.initialize(getSettings());
            instance.prepare(engine);
            instance.determineCPE(commonValidator);
            instance.determineCPE(struts);
            instance.determineCPE(spring);
            instance.determineCPE(spring3);
            instance.close();

            String expResult = "cpe:/a:apache:struts:2.1.2";

            for (Identifier i : commonValidator.getIdentifiers()) {
                assertFalse("Apache Common Validator - found a CPE identifier?", "cpe".equals(i.getType()));
            }

            assertTrue("Incorrect match size - struts", struts.getIdentifiers().size() >= 1);
            boolean found = false;
            for (Identifier i : struts.getIdentifiers()) {
                if (expResult.equals(i.getValue())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Incorrect match - struts", found);
            assertTrue("Incorrect match size - spring3 - " + spring3.getIdentifiers().size(), spring3.getIdentifiers().size() >= 1);

            jarAnalyzer.close();
        }
    }

    /**
     * Test of determineIdentifiers method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineIdentifiers() throws Exception {
        Dependency openssl = new Dependency();
        openssl.addEvidence(EvidenceType.VENDOR, "test", "vendor", "openssl", Confidence.HIGHEST);
        openssl.addEvidence(EvidenceType.PRODUCT, "test", "product", "openssl", Confidence.HIGHEST);
        openssl.addEvidence(EvidenceType.VERSION, "test", "version", "1.0.1c", Confidence.HIGHEST);

        CPEAnalyzer instance = new CPEAnalyzer();
        try (Engine engine = new Engine(getSettings())) {
            engine.openDatabase(true, true);
            instance.initialize(getSettings());
            instance.prepare(engine);
            instance.determineIdentifiers(openssl, "openssl", "openssl", Confidence.HIGHEST);
            instance.close();
        }

        String expResult = "cpe:/a:openssl:openssl:1.0.1c";
        Identifier expIdentifier = new Identifier("cpe", expResult, expResult);
        boolean found = false;
        for (Identifier i : openssl.getIdentifiers()) {
            if (expResult.equals(i.getValue())) {
                found = true;
                break;
            }
        }
        assertTrue("OpenSSL identifier not found", found);
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
        try (Engine engine = new Engine(getSettings())) {
            engine.openDatabase(true, true);
            instance.initialize(getSettings());
            instance.prepare(engine);

            Set<String> productWeightings = Collections.singleton("struts2");
            Set<String> vendorWeightings = Collections.singleton("apache");
            List<IndexEntry> result = instance.searchCPE(vendor, product, vendorWeightings, productWeightings);

            boolean found = false;
            for (IndexEntry entry : result) {
                if (expVendor.equals(entry.getVendor()) && expProduct.equals(entry.getProduct())) {
                    found = true;
                    break;
                }
            }
            assertTrue("apache:struts was not identified", found);
        }
        instance.close();
    }
}
