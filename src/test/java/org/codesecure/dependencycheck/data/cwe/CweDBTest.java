/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.cwe;

import java.io.ObjectOutputStream;
import java.io.FileOutputStream;
import java.util.Map;
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
public class CweDBTest {

    public CweDBTest() {
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

    /**
     * Method to serialize the CWE HashMap. This is not used in
     * production; this is only used once during dev to create
     * the serialized hashmap.
     */
//    @Test
//    public void testUpdate() throws Exception {
//        SAXParserFactory factory = SAXParserFactory.newInstance();
//        SAXParser saxParser = factory.newSAXParser();
//
//        CweHandler handler = new CweHandler();
//        File file = new File(this.getClass().getClassLoader().getResource("cwe.2000.xml").getPath());
//
//        saxParser.parse(file, handler);
//        System.out.println("Found " + handler.getCwe().size() + " cwe entries.");
//        Map<String,String> cwe = handler.getCwe();
//        FileOutputStream fout = new FileOutputStream("src/main/resources/data/cwe.hashmap.serialized");
//        ObjectOutputStream objOut = new ObjectOutputStream(fout);
//        objOut.writeObject(cwe);
//        objOut.close();
//    }

    /**
     * Test of getCweName method, of class CweDB.
     */
    @Test
    public void testGetCweName() {
        System.out.println("getCweName");
        String cweId = "CWE-16";
        String expResult = "Configuration";
        String result = CweDB.getCweName(cweId);
        assertEquals(expResult, result);
    }
}
