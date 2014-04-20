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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * A simple validating parser for XML Suppression Rules.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class SuppressionParser {
    
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(SuppressionParser.class.getName());
    /**
     * JAXP Schema Language. Source: http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String JAXP_SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
    /**
     * W3C XML Schema. Source: http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String W3C_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";
    /**
     * JAXP Schema Source. Source: http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String JAXP_SCHEMA_SOURCE = "http://java.sun.com/xml/jaxp/properties/schemaSource";

    /**
     * Parses the given xml file and returns a list of the suppression rules contained.
     *
     * @param file an xml file containing suppression rules
     * @return a list of suppression rules
     * @throws SuppressionParseException thrown if the xml file cannot be parsed
     */
    public List<SuppressionRule> parseSuppressionRules(File file) throws SuppressionParseException {
        try {
            final InputStream schemaStream = this.getClass().getClassLoader().getResourceAsStream("schema/suppression.xsd");
            final SuppressionHandler handler = new SuppressionHandler();

            final SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setValidating(true);
            final SAXParser saxParser = factory.newSAXParser();
            saxParser.setProperty(SuppressionParser.JAXP_SCHEMA_LANGUAGE, SuppressionParser.W3C_XML_SCHEMA);
            saxParser.setProperty(SuppressionParser.JAXP_SCHEMA_SOURCE, new InputSource(schemaStream));
            final XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setErrorHandler(new SuppressionErrorHandler());
            xmlReader.setContentHandler(handler);

            final InputStream inputStream = new FileInputStream(file);
            final Reader reader = new InputStreamReader(inputStream, "UTF-8");
            final InputSource in = new InputSource(reader);
            //in.setEncoding("UTF-8");

            xmlReader.parse(in);

            return handler.getSuppressionRules();
        } catch (ParserConfigurationException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new SuppressionParseException(ex);
        } catch (SAXException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new SuppressionParseException(ex);
        } catch (FileNotFoundException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new SuppressionParseException(ex);
        } catch (IOException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new SuppressionParseException(ex);
        }
    }
}
