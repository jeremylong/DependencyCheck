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
            Logger.getLogger(SuppressionParser.class.getName()).log(Level.FINE, null, ex);
            throw new SuppressionParseException(ex);
        } catch (SAXException ex) {
            Logger.getLogger(SuppressionParser.class.getName()).log(Level.FINE, null, ex);
            throw new SuppressionParseException(ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(SuppressionParser.class.getName()).log(Level.FINE, null, ex);
            throw new SuppressionParseException(ex);
        } catch (IOException ex) {
            Logger.getLogger(SuppressionParser.class.getName()).log(Level.FINE, null, ex);
            throw new SuppressionParseException(ex);
        }
    }
}
