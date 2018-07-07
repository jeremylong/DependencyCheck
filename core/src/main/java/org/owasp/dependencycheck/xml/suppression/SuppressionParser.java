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
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;

import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.XmlUtils;

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
@ThreadSafe
public class SuppressionParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionParser.class);
    /**
     * The suppression schema file location for v 1.2.
     */
    public static final String SUPPRESSION_SCHEMA_1_2 = "schema/dependency-suppression.1.2.xsd";
    /**
     * The suppression schema file location for v1.1.
     */
    public static final String SUPPRESSION_SCHEMA_1_1 = "schema/dependency-suppression.1.1.xsd";
    /**
     * The old suppression schema file location for v1.0.
     */
    private static final String SUPPRESSION_SCHEMA_1_0 = "schema/suppression.xsd";

    /**
     * Parses the given XML file and returns a list of the suppression rules
     * contained.
     *
     * @param file an XML file containing suppression rules
     * @return a list of suppression rules
     * @throws SuppressionParseException thrown if the XML file cannot be parsed
     */
    public List<SuppressionRule> parseSuppressionRules(File file) throws SuppressionParseException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return parseSuppressionRules(fis);
        } catch (SAXException | IOException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
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
        try (
                InputStream schemaStream12 = FileUtils.getResourceAsStream(SUPPRESSION_SCHEMA_1_2);
                InputStream schemaStream11 = FileUtils.getResourceAsStream(SUPPRESSION_SCHEMA_1_1);
                InputStream schemaStream10 = FileUtils.getResourceAsStream(SUPPRESSION_SCHEMA_1_0);
            ) {
            final SuppressionHandler handler = new SuppressionHandler();
            final SAXParser saxParser = XmlUtils.buildSecureSaxParser(schemaStream12, schemaStream11, schemaStream10);
            final XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setErrorHandler(new SuppressionErrorHandler());
            xmlReader.setContentHandler(handler);
            try (Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
                final InputSource in = new InputSource(reader);
                xmlReader.parse(in);
                return handler.getSuppressionRules();
            }
        } catch (ParserConfigurationException | FileNotFoundException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        } catch (SAXException ex) {
            if (ex.getMessage().contains("Cannot find the declaration of element 'suppressions'.")) {
                throw ex;
            } else {
                LOGGER.debug("", ex);
                throw new SuppressionParseException(ex);
            }
        } catch (IOException ex) {
            LOGGER.debug("", ex);
            throw new SuppressionParseException(ex);
        }
    }
}
