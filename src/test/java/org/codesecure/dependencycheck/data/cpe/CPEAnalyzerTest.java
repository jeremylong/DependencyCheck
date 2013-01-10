/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.cpe;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.queryparser.classic.ParseException;
import org.codesecure.dependencycheck.dependency.Dependency;
import org.codesecure.dependencycheck.analyzer.JarAnalyzer;
import org.junit.Test;

/**
 *
 * @author jeremy
 */
public class CPEAnalyzerTest extends BaseIndexTestCase {

    public CPEAnalyzerTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Tests of buildSearch of class CPEAnalyzer.
     * @throws IOException is thrown when an IO Exception occurs.
     * @throws CorruptIndexException is thrown when the index is corrupt.
     * @throws ParseException is thrown when a parse exception occurs
     */
    @Test
    public void testBuildSearch() throws IOException, CorruptIndexException, ParseException {
        System.out.println("buildSearch");
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
        assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, version, null, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  AND  vendor:( apache software foundation )  AND version:(2.1.2^0.2 )";
        assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, version, vendorWeightings, null);
        expResult = " product:( struts 2 core )  AND  vendor:(  apache^5 software foundation )  AND version:(2.1.2^0.2 )";
        assertTrue(expResult.equals(queryText));

        queryText = instance.buildSearch(vendor, product, version, vendorWeightings, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  AND  vendor:(  apache^5 software foundation )  AND version:(2.1.2^0.2 )";
        assertTrue(expResult.equals(queryText));
    }

    /**
     * Test of open method, of class CPEAnalyzer.
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testOpen() throws Exception {
        System.out.println("open");
        CPEAnalyzer instance = new CPEAnalyzer();
        assertFalse(instance.isOpen());
        instance.open();
        assertTrue(instance.isOpen());
        instance.close();
        assertFalse(instance.isOpen());
    }

    /**
     * Test of determineCPE method, of class CPEAnalyzer.
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineCPE() throws Exception {
        System.out.println("determineCPE");
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        JarAnalyzer jarAnalyzer = new JarAnalyzer();
        Dependency depends = new Dependency(file);
        jarAnalyzer.analyze(depends, null);

        File fileSpring = new File(this.getClass().getClassLoader().getResource("spring-core-2.5.5.jar").getPath());
        Dependency spring = new Dependency(fileSpring);
        jarAnalyzer.analyze(spring, null);

        CPEAnalyzer instance = new CPEAnalyzer();
        instance.open();
        String expResult = "cpe:/a:apache:struts:2.1.2";
        instance.determineCPE(depends);
        instance.determineCPE(spring);
        instance.close();
        assertTrue("Incorrect match", depends.getIdentifiers().size() == 1);
        assertTrue("Incorrect match", depends.getIdentifiers().get(0).getValue().equals(expResult));
    }


    /**
     * Test of searchCPE method, of class CPEAnalyzer.
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testSearchCPE() throws Exception {
        System.out.println("searchCPE");
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
        assertEquals(expResult, result.get(0).getName());


        instance.close();
    }
}
