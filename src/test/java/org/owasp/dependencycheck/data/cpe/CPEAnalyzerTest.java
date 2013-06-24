/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import org.owasp.dependencycheck.data.cpe.Entry;
import org.owasp.dependencycheck.data.cpe.CPEAnalyzer;
import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.queryparser.classic.ParseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.junit.Assert;
import org.junit.Test;
import org.owasp.dependencycheck.dependency.Identifier;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class CPEAnalyzerTest extends BaseIndexTestCase {

    /**
     * Tests of buildSearch of class CPEAnalyzer.
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

        String queryText = instance.buildSearch(vendor, product, version, null, null);
        String expResult = " product:( struts 2 core )  AND  vendor:( apache software foundation )  AND version:(2.1.2^0.7 )";
        Assert.assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, version, null, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  AND  vendor:( apache software foundation )  AND version:(2.1.2^0.2 )";
        Assert.assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, version, vendorWeightings, null);
        expResult = " product:( struts 2 core )  AND  vendor:(  apache^5 software foundation )  AND version:(2.1.2^0.2 )";
        Assert.assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, version, vendorWeightings, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  AND  vendor:(  apache^5 software foundation )  AND version:(2.1.2^0.2 )";
        Assert.assertTrue(expResult.equals(queryText));
    }

    /**
     * Test of open method, of class CPEAnalyzer.
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testOpen() throws Exception {
        CPEAnalyzer instance = new CPEAnalyzer();
        Assert.assertFalse(instance.isOpen());
        instance.open();
        Assert.assertTrue(instance.isOpen());
        instance.close();
        Assert.assertFalse(instance.isOpen());
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineCPE() throws Exception {
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        JarAnalyzer jarAnalyzer = new JarAnalyzer();
        Dependency depends = new Dependency(file);
        jarAnalyzer.analyze(depends, null);

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
        instance.determineCPE(depends);
        instance.determineCPE(spring);
        instance.determineCPE(spring3);
        instance.close();

        String expResult = "cpe:/a:apache:struts:2.1.2";
        Identifier expIdentifier = new Identifier("cpe", expResult, expResult);
        String expResultSpring = "cpe:/a:springsource:spring_framework:2.5.5";
        String expResultSpring3 = "cpe:/a:vmware:springsource_spring_framework:3.0.0";

        Assert.assertTrue("Apache Common Validator - found an identifier?", commonValidator.getIdentifiers().isEmpty());
        Assert.assertTrue("Incorrect match size - struts", depends.getIdentifiers().size() >= 1);
        Assert.assertTrue("Incorrect match - struts", depends.getIdentifiers().contains(expIdentifier));
        Assert.assertTrue("Incorrect match size - spring3 - " + spring3.getIdentifiers().size(), spring3.getIdentifiers().size() >= 1);

        //the following two only work if the HintAnalyzer is used.
        //Assert.assertTrue("Incorrect match size - spring", spring.getIdentifiers().size() == 1);
        //Assert.assertTrue("Incorrect match - spring", spring.getIdentifiers().get(0).getValue().equals(expResultSpring));

    }

    /**
     * Test of searchCPE method, of class CPEAnalyzer.
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

        List<Entry> result = instance.searchCPE(vendor, product, version, productWeightings, vendorWeightings);
        Assert.assertEquals(expResult, result.get(0).getName());


        instance.close();
    }
}
