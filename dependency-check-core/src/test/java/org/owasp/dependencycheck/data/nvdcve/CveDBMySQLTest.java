/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.data.nvdcve;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author jeremy
 */
public class CveDBMySQLTest {

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    /**
     * Pretty useless tests of open, commit, and close methods, of class CveDB.
     */
    @Test
    public void testOpen() throws Exception {
        /*
         CveDB instance = new CveDB();
         instance.open();
         instance.commit();
         instance.close();
         */
    }

    /**
     * Test of getCPEs method, of class CveDB.
     */
    @Test
    public void testGetCPEs() throws Exception {
        /*
         CveDB instance = new CveDB();
         try {
         String vendor = "apache";
         String product = "struts";
         instance.open();
         Set<VulnerableSoftware> result = instance.getCPEs(vendor, product);
         assertTrue(result.size() > 5);
         } finally {
         instance.close();
         }
         */
    }

    /**
     * Test of getVulnerabilities method, of class CveDB.
     */
    @Test
    public void testGetVulnerabilities() throws Exception {
        /*
         String cpeStr = "cpe:/a:apache:struts:2.1.2";
         CveDB instance = new CveDB();
         try {
         instance.open();
         List result = instance.getVulnerabilities(cpeStr);
         assertTrue(result.size() > 5);
         } finally {
         instance.close();
         }
         */
    }
}
