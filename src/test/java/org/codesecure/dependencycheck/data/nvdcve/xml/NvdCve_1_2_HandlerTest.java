/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve.xml;

import java.io.File;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.codesecure.dependencycheck.dependency.VulnerableSoftware;
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
public class NvdCve_1_2_HandlerTest {

    public NvdCve_1_2_HandlerTest() {
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
    public void testParse() throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser saxParser = factory.newSAXParser();

        File file = new File(this.getClass().getClassLoader().getResource("nvdcve-2012.xml").getPath());

        NvdCve12Handler instance = new NvdCve12Handler();
        saxParser.parse(file, instance);
        Map<String, List<VulnerableSoftware>> results = instance.getVulnerabilities();
        assertTrue("No vulnerable software identified with a previous version in 2012 CVE 1.2?", !results.isEmpty());
    }
}
