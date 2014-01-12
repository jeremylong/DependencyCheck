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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.suppression;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.List;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class SuppressionHandlerTest {

    public SuppressionHandlerTest() {
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
     * Test of getSuppressionRules method, of class SuppressionHandler.
     *
     * @throws Exception thrown if there is an exception....
     */
    @Test
    public void testHandler() throws Exception {
        File file = new File(this.getClass().getClassLoader().getResource("suppressions.xml").getPath());

        File schema = new File(this.getClass().getClassLoader().getResource("schema/suppression.xsd").getPath());
        SuppressionHandler handler = new SuppressionHandler();

        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setValidating(true);
        SAXParser saxParser = factory.newSAXParser();
        saxParser.setProperty(SuppressionParser.JAXP_SCHEMA_LANGUAGE, SuppressionParser.W3C_XML_SCHEMA);
        saxParser.setProperty(SuppressionParser.JAXP_SCHEMA_SOURCE, schema);
        XMLReader xmlReader = saxParser.getXMLReader();
        xmlReader.setErrorHandler(new SuppressionErrorHandler());
        xmlReader.setContentHandler(handler);

        InputStream inputStream = new FileInputStream(file);
        Reader reader = new InputStreamReader(inputStream, "UTF-8");
        InputSource in = new InputSource(reader);
        //in.setEncoding("UTF-8");

        xmlReader.parse(in);

        List result = handler.getSuppressionRules();
        assertTrue(result.size() > 3);
    }
}
