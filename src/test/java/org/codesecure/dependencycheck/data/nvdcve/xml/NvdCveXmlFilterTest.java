/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve.xml;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.MalformedURLException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import org.codesecure.dependencycheck.data.nvdcve.generated.VulnerabilityType;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 *
 * @author Jeremy
 */
public class NvdCveXmlFilterTest {
    
    public NvdCveXmlFilterTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of process method, of class NvdCveXmlFilter.
     */
    @Test
    public void testFilter() throws JAXBException, SAXException, ParserConfigurationException, MalformedURLException, IOException {
        System.out.println("filter");
        
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setNamespaceAware(true);
        XMLReader reader = factory.newSAXParser().getXMLReader();
        
        JAXBContext context = JAXBContext.newInstance("org.codesecure.dependencycheck.data.nvdcve.generated");
        NvdCveXmlFilter filter = new NvdCveXmlFilter(context);

        reader.setContentHandler(filter);
        File file = new File(this.getClass().getClassLoader().getResource("nvdcve-2.0-2012.xml").getPath());
        Reader fileReader = new FileReader(file);
        InputSource is = new InputSource(fileReader);
        reader.parse(is);
    }
}
