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
package org.owasp.dependencycheck.xml.suppression;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * A simple validating parser for XML Suppression Rules.
 *
 * @author Jeremy Long
 */
public class SuppressionParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionParser.class);
    /**
     * JAXP Schema Language. Source:
     * http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String JAXP_SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
    /**
     * W3C XML Schema. Source:
     * http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String W3C_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";
    /**
     * JAXP Schema Source. Source:
     * http://docs.oracle.com/javase/tutorial/jaxp/sax/validation.html
     */
    public static final String JAXP_SCHEMA_SOURCE = "http://java.sun.com/xml/jaxp/properties/schemaSource";
    /**
     * The suppression schema file location.
     */
    private static final String SUPPRESSION_SCHEMA = "schema/dependency-suppression.1.1.xsd";
    /**
     * The old suppression schema file location.
     */
    private static final String OLD_SUPPRESSION_SCHEMA = "schema/suppression.xsd";

    /**
     * Parses the given XML file and returns a list of the suppression rules
     * contained.
     *
     * @param file an XML file containing suppression rules
     * @return a list of suppression rules
     * @throws SuppressionParseException thrown if the XML file cannot be parsed
     */
    public List<SuppressionRule> parseSuppressionRules(File file) throws SuppressionParseException {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            return parseSuppressionRules(fis);
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } catch (SAXException ex) {
            try {
                if (fis != null) {
                    try {
                        fis.close();
                    } catch (IOException ex1) {
                        LOGGER.debug("Unable to close stream", ex1);
                    }
                }
                fis = new FileInputStream(file);
            } catch (FileNotFoundException ex1) {
                throw new SuppressionParseException(ex);
            }
            return parseOldSuppressionRules(fis);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ex) {
                    LOGGER.debug("Unable to close stream", ex);
                }
            }
        }
    }

    /**
     * Parses the given XML stream and returns a list of the suppression rules
     * contained.
     *
     * @param inputStream an InputStream containing suppression rules
     * @return a list of suppression rules
     * @throws SuppressionParseException thrown if the XML cannot be parsed
     * @throws SAXException thrown if the XML cannot be parsed
     */
    public List<SuppressionRule> parseSuppressionRules(InputStream inputStream) throws SuppressionParseException, SAXException {
        InputStream schemaStream = null;
        try {
            schemaStream = this.getClass().getClassLoader().getResourceAsStream(SUPPRESSION_SCHEMA);
            final SuppressionHandler handler = new SuppressionHandler();
            final SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setValidating(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            final SAXParser saxParser = factory.newSAXParser();
            saxParser.setProperty(SuppressionParser.JAXP_SCHEMA_LANGUAGE, SuppressionParser.W3C_XML_SCHEMA);
            saxParser.setProperty(SuppressionParser.JAXP_SCHEMA_SOURCE, new InputSource(schemaStream));
            final XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setErrorHandler(new SuppressionErrorHandler());
            xmlReader.setContentHandler(handler);

            final Reader reader = new InputStreamReader(inputStream, "UTF-8");
            final InputSource in = new InputSource(reader);
            //in.setEncoding("UTF-8");

            xmlReader.parse(in);

            return handler.getSuppressionRules();
        } catch (ParserConfigurationException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } catch (SAXException ex) {
            if (ex.getMessage().contains("Cannot find the declaration of element 'suppressions'.")) {
                throw ex;
            } else {
                LOGGER.debug("", ex);
                throw new SuppressionParseException(ex);
            }
        } catch (FileNotFoundException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } finally {
            if (schemaStream != null) {
                try {
                    schemaStream.close();
                } catch (IOException ex) {
                    LOGGER.debug("Error closing suppression file stream", ex);
                }
            }
        }
    }

    /**
     * Parses the given XML stream and returns a list of the suppression rules
     * contained.
     *
     * @param inputStream an InputStream containing suppression rues
     * @return a list of suppression rules
     * @throws SuppressionParseException if the XML cannot be parsed
     */
    private List<SuppressionRule> parseOldSuppressionRules(InputStream inputStream) throws SuppressionParseException {
        InputStream schemaStream = null;
        try {
            schemaStream = this.getClass().getClassLoader().getResourceAsStream(OLD_SUPPRESSION_SCHEMA);
            final SuppressionHandler handler = new SuppressionHandler();
            final SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setNamespaceAware(true);
            factory.setValidating(true);
            final SAXParser saxParser = factory.newSAXParser();
            saxParser.setProperty(SuppressionParser.JAXP_SCHEMA_LANGUAGE, SuppressionParser.W3C_XML_SCHEMA);
            saxParser.setProperty(SuppressionParser.JAXP_SCHEMA_SOURCE, new InputSource(schemaStream));
            final XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setErrorHandler(new SuppressionErrorHandler());
            xmlReader.setContentHandler(handler);

            final Reader reader = new InputStreamReader(inputStream, "UTF-8");
            final InputSource in = new InputSource(reader);

            xmlReader.parse(in);

            return handler.getSuppressionRules();
        } catch (ParserConfigurationException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } catch (SAXException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } catch (FileNotFoundException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } finally {
            if (schemaStream != null) {
                try {
                    schemaStream.close();
                } catch (IOException ex) {
                    LOGGER.debug("Error closing old suppression file stream", ex);
                }
            }
        }
    }
}
