/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve.xml;

import java.io.File;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class NvdCve_2_0_HandlerTest {

    public NvdCve_2_0_HandlerTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testParse() {
        Exception results = null;
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser saxParser = factory.newSAXParser();

            File file = new File(this.getClass().getClassLoader().getResource("nvdcve-2.0-2012.xml").getPath());

            NvdCve20Handler instance = new NvdCve20Handler();

            saxParser.parse(file, instance);
        } catch (Exception ex) {
            results = ex;
        }
        assertTrue("Exception thrown during parse of 2012 CVE version 2.0?", results == null);
        if (results != null) {
            System.err.println(results);
        }

    }
}
