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
import org.apache.lucene.queryParser.ParseException;
import org.codesecure.dependencycheck.data.BaseIndexTestCase;
import org.codesecure.dependencycheck.scanner.Dependency;
import org.codesecure.dependencycheck.scanner.JarAnalyzer;
import org.junit.Test;

/**
 *
 * @author jeremy
 */
public class CPEQueryTest extends BaseIndexTestCase {
    
    public CPEQueryTest(String testName) {
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
     * Test of locate method, of class CPEQuery.
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testLocate() throws Exception {
        System.out.println("locate");
        String vendor = "apache software foundation";
        String product = "struts 2 core";
        String version = "2.1.2";
        CPEQuery instance = new CPEQuery();
        instance.open();
        String expResult = "cpe:/a:apache:struts:2.1.2";
        List<Entry> result = instance.searchCPE(vendor, product, version);
        assertEquals(expResult, result.get(0).getName());
        
        //TODO - yeah, not a very good test as the results are the same with or without weighting...
        Set<String> productWeightings = new HashSet<String>(1);
        productWeightings.add("struts2");

        Set<String> vendorWeightings = new HashSet<String>(1);
        vendorWeightings.add("apache");
        
        result = instance.searchCPE(vendor, product, version,productWeightings,vendorWeightings);
        assertEquals(expResult, result.get(0).getName());

        vendor = "apache software foundation";
        product = "struts 2 core";
        version = "2.3.1.2";

        //yes, this isn't right. we verify this with another method later
        expResult = "cpe:/a:apache:struts"; 
        result = instance.searchCPE(vendor, product, version);
        boolean startsWith = result.get(0).getName().startsWith(expResult);
        assertTrue("CPE does not begin with apache struts",startsWith);
        instance.close();
    }
    
    /**
     * Tests of buildSearch of class CPEQuery.
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
        CPEQuery instance = new CPEQuery();

        String queryText = instance.buildSearch(vendor, product, version, null, null);
        String expResult = " product:( struts 2 core )  vendor:( apache software foundation ) version:(2.1.2)";
        assertTrue(expResult.equals(queryText));
        
        queryText = instance.buildSearch(vendor, product, version, null, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  vendor:( apache software foundation ) version:(2.1.2^0.2 )";
        assertTrue(expResult.equals(queryText));
        
        queryText = instance.buildSearch(vendor, product, version,vendorWeightings,null);
        expResult = " product:( struts 2 core )  vendor:(  apache^5 software foundation ) version:(2.1.2^0.2 )";
        assertTrue(expResult.equals(queryText));
    
        queryText = instance.buildSearch(vendor, product, version, vendorWeightings, productWeightings);
        expResult = " product:(  struts^5 struts2^5 2 core )  vendor:(  apache^5 software foundation ) version:(2.1.2^0.2 )";
        assertTrue(expResult.equals(queryText));
    }

    /**
     * Test of open method, of class CPEQuery.
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testOpen() throws Exception {
        System.out.println("open");
        CPEQuery instance = new CPEQuery();
        assertFalse(instance.isOpen());
        instance.open();
        assertTrue(instance.isOpen());
        instance.close();
        assertFalse(instance.isOpen());
    }


    /**
     * Test of determineCPE method, of class CPEQuery.
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testDetermineCPE() throws Exception {
        System.out.println("determineCPE");
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        JarAnalyzer jarAnalyzer = new JarAnalyzer();
        Dependency depends = jarAnalyzer.insepct(file);
        CPEQuery instance = new CPEQuery();
        instance.open();
        String expResult = "cpe:/a:apache:struts:2.1.2";
        instance.determineCPE(depends);
        instance.close();
        assertTrue(depends.getCPEs().contains(expResult));
        assertTrue(depends.getCPEs().size()==1);

    }

    /**
     * Test of searchCPE method, of class CPEQuery.
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testSearchCPE_3args() throws Exception {
        System.out.println("searchCPE - 3 args");
        System.out.println("searchCPE");
        String vendor = "apache software foundation";
        String product = "struts 2 core";
        String version = "2.1.2";
        CPEQuery instance = new CPEQuery();
        instance.open();
        String expResult = "cpe:/a:apache:struts:2.1.2";
        List<Entry> result = instance.searchCPE(vendor, product, version);
        assertEquals(expResult, result.get(0).getName());
        
        vendor = "apache software foundation";
        product = "struts 2 core";
        version = "2.3.1.2";

        expResult = "cpe:/a:apache:struts";
        result = instance.searchCPE(vendor, product, version);
        boolean startsWith = result.get(0).getName().startsWith(expResult);
        assertTrue("CPE Does not start with apache struts.", startsWith);
        
        instance.close();
    }

    /**
     * Test of searchCPE method, of class CPEQuery.
     * @throws Exception is thrown when an exception occurs
     */
    @Test
    public void testSearchCPE_5args() throws Exception {
        System.out.println("searchCPE - 5 args");
        String vendor = "apache software foundation";
        String product = "struts 2 core";
        String version = "2.1.2";
        String expResult = "cpe:/a:apache:struts:2.1.2";
        
        CPEQuery instance = new CPEQuery();
        instance.open();
        
        //TODO - yeah, not a very good test as the results are the same with or without weighting...
        Set<String> productWeightings = new HashSet<String>(1);
        productWeightings.add("struts2");

        Set<String> vendorWeightings = new HashSet<String>(1);
        vendorWeightings.add("apache");
        
        List<Entry> result = instance.searchCPE(vendor, product, version,productWeightings,vendorWeightings);
        assertEquals(expResult, result.get(0).getName());

        
        instance.close();
    }

}
