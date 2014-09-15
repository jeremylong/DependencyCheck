/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

        List<SuppressionRule> result = handler.getSuppressionRules();
        assertTrue(result.size() > 3);
        int baseCount = 0;
        for (SuppressionRule r : result) {
            if (r.isBase()) {
                baseCount++;
            }
        }
        assertTrue(baseCount > 0);

    }
}
