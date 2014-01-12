/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.queryparser.classic.ParseException;
import org.junit.After;
import org.junit.AfterClass;
import org.owasp.dependencycheck.dependency.Dependency;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.data.cpe.BaseIndexTestCase;
import org.owasp.dependencycheck.data.cpe.IndexEntry;
import org.owasp.dependencycheck.dependency.Identifier;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class CPEAnalyzerTest extends BaseIndexTestCase {

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Tests of buildSearch of class CPEAnalyzer.
     *
     * @throws IOException is thrown when an IO Exception occurs.
     * @throws CorruptIndexException is thrown when the index is corrupt.
     * @throws ParseException is thrown when a parse exception occurs
     */
    @Test
    public void testBuildSearch() throws IOException, CorruptIndexException, ParseException {
        Set<String> productWeightings = new HashSet<String>(1);
        productWeightings.add("struts2");

        Set<String> vendorWeightings = new HashSet<String>(1);
        vendorWeightings.add("apache");

        String vendor = "apache software foundation";
        String product = "struts 2 core";
        String version = "2.1.2";
        CPEAnalyzer instance = new CPEAnalyzer();

        String queryText = instance.buildSearch(vendor, product, null, null);
        String expResult = " product:( struts 2 core )  AND  vendor:( apache software foundation ) ";
        Assert.assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, null, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  AND  vendor:( apache software foundation ) ";
        Assert.assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, vendorWeightings, null);
        expResult = " product:( struts 2 core )  AND  vendor:(  apache^5 software foundation ) ";
        Assert.assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, vendorWeightings, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  AND  vendor:(  apache^5 software foundation ) ";
        Assert.assertTrue(expResult.equals(queryText));
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineCPE_full() throws Exception {
        callDetermineCPE_full("hazelcast-2.5.jar", null);
        callDetermineCPE_full("spring-context-support-2.5.5.jar", "cpe:/a:vmware:springsource_spring_framework:2.5.5");
        callDetermineCPE_full("spring-core-3.0.0.RELEASE.jar", "cpe:/a:vmware:springsource_spring_framework:3.0.0");
        callDetermineCPE_full("org.mortbay.jetty.jar", "cpe:/a:mortbay_jetty:jetty:4.2");
        callDetermineCPE_full("jaxb-xercesImpl-1.5.jar", null);
        callDetermineCPE_full("ehcache-core-2.2.0.jar", null);
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    public void callDetermineCPE_full(String depName, String expResult) throws Exception {

        File file = new File(this.getClass().getClassLoader().getResource(depName).getPath());

        Dependency dep = new Dependency(file);

        FileNameAnalyzer fnAnalyzer = new FileNameAnalyzer();
        fnAnalyzer.analyze(dep, null);

        JarAnalyzer jarAnalyzer = new JarAnalyzer();
        jarAnalyzer.analyze(dep, null);
        HintAnalyzer hAnalyzer = new HintAnalyzer();
        hAnalyzer.analyze(dep, null);


        CPEAnalyzer instance = new CPEAnalyzer();
        instance.open();
        instance.analyze(dep, null);
        instance.close();
        FalsePositiveAnalyzer fp = new FalsePositiveAnalyzer();
        fp.analyze(dep, null);

//        for (Identifier i : dep.getIdentifiers()) {
//            System.out.println(i.getValue());
//        }
        if (expResult != null) {
            Identifier expIdentifier = new Identifier("cpe", expResult, expResult);
            Assert.assertTrue("Incorrect match: { dep:'" + dep.getFileName() + "' }", dep.getIdentifiers().contains(expIdentifier));
        } else if (dep.getIdentifiers().isEmpty()) {
            Assert.assertTrue("Match found when an Identifier should not have been found: { dep:'" + dep.getFileName() + "' }", dep.getIdentifiers().isEmpty());
        } else {
            Assert.assertTrue("Match found when an Identifier should not have been found: { dep:'" + dep.getFileName() + "', identifier:'" + dep.getIdentifiers().iterator().next().getValue() + "' }", dep.getIdentifiers().isEmpty());
        }
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     *
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineCPE() throws Exception {
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        //File file = new File(this.getClass().getClassLoader().getResource("axis2-adb-1.4.1.jar").getPath());
        Dependency struts = new Dependency(file);

        FileNameAnalyzer fnAnalyzer = new FileNameAnalyzer();
        fnAnalyzer.analyze(struts, null);

        JarAnalyzer jarAnalyzer = new JarAnalyzer();
        jarAnalyzer.analyze(struts, null);


        File fileCommonValidator = new File(this.getClass().getClassLoader().getResource("commons-validator-1.4.0.jar").getPath());
        Dependency commonValidator = new Dependency(fileCommonValidator);
        jarAnalyzer.analyze(commonValidator, null);

        File fileSpring = new File(this.getClass().getClassLoader().getResource("spring-core-2.5.5.jar").getPath());
        Dependency spring = new Dependency(fileSpring);
        jarAnalyzer.analyze(spring, null);

        File fileSpring3 = new File(this.getClass().getClassLoader().getResource("spring-core-3.0.0.RELEASE.jar").getPath());
        Dependency spring3 = new Dependency(fileSpring3);
        jarAnalyzer.analyze(spring3, null);

        CPEAnalyzer instance = new CPEAnalyzer();
        instance.open();
        instance.determineCPE(commonValidator);
        instance.determineCPE(struts);
        instance.determineCPE(spring);
        instance.determineCPE(spring3);
        instance.close();

        String expResult = "cpe:/a:apache:struts:2.1.2";
        Identifier expIdentifier = new Identifier("cpe", expResult, expResult);
        String expResultSpring = "cpe:/a:springsource:spring_framework:2.5.5";
        String expResultSpring3 = "cpe:/a:vmware:springsource_spring_framework:3.0.0";

        Assert.assertTrue("Apache Common Validator - found an identifier?", commonValidator.getIdentifiers().isEmpty());
        Assert.assertTrue("Incorrect match size - struts", struts.getIdentifiers().size() >= 1);
        Assert.assertTrue("Incorrect match - struts", struts.getIdentifiers().contains(expIdentifier));
        Assert.assertTrue("Incorrect match size - spring3 - " + spring3.getIdentifiers().size(), spring3.getIdentifiers().size() >= 1);

        //the following two only work if the HintAnalyzer is used.
        //Assert.assertTrue("Incorrect match size - spring", spring.getIdentifiers().size() == 1);
        //Assert.assertTrue("Incorrect match - spring", spring.getIdentifiers().get(0).getValue().equals(expResultSpring));

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
        String version = "2.1.2";
        String expResult = "cpe:/a:apache:struts:2.1.2";

        CPEAnalyzer instance = new CPEAnalyzer();
        instance.open();

        //TODO - yeah, not a very good test as the results are the same with or without weighting...
        Set<String> productWeightings = new HashSet<String>(1);
        productWeightings.add("struts2");

        Set<String> vendorWeightings = new HashSet<String>(1);
        vendorWeightings.add("apache");

        List<IndexEntry> result = instance.searchCPE(vendor, product, productWeightings, vendorWeightings);
        //TODO fix this assert
        //Assert.assertEquals(expResult, result.get(0).getName());


        instance.close();
    }
}
