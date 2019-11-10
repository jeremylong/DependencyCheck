/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.SAXParseException;

/**
 * Collection of XML related code.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public final class XmlUtils {

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
     * Private constructor for a utility class.
     */
    private XmlUtils() {
    }

    /**
     * Constructs a validating secure SAX Parser.
     *
     * @param schemaStream One or more inputStreams with the schema(s) that the
     * parser should be able to validate the XML against, one InputStream per
     * schema
     * @return a SAX Parser
     * @throws javax.xml.parsers.ParserConfigurationException is thrown if there
     * is a parser configuration exception
     * @throws org.xml.sax.SAXNotRecognizedException thrown if there is an
     * unrecognized feature
     * @throws org.xml.sax.SAXNotSupportedException thrown if there is a
     * non-supported feature
     * @throws org.xml.sax.SAXException is thrown if there is a
     * org.xml.sax.SAXException
     */
    public static SAXParser buildSecureSaxParser(InputStream... schemaStream) throws ParserConfigurationException,
            SAXNotRecognizedException, SAXNotSupportedException, SAXException {
        final SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setValidating(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        String accessExternalSchema = System.getProperty("javax.xml.accessExternalSchema");
        if (accessExternalSchema == null) {
            accessExternalSchema = "file, https";
        } else if (!"ALL".equalsIgnoreCase(accessExternalSchema)) {
            if (!accessExternalSchema.contains("file")) {
                accessExternalSchema += ", file";
            }
            if (!accessExternalSchema.contains("https")) {
                accessExternalSchema += ", https";
            }
        }
        System.setProperty("javax.xml.accessExternalSchema", accessExternalSchema);

        final SAXParser saxParser = factory.newSAXParser();
        saxParser.setProperty(JAXP_SCHEMA_LANGUAGE, W3C_XML_SCHEMA);
        saxParser.setProperty(JAXP_SCHEMA_SOURCE, schemaStream);
        return saxParser;
    }

    /**
     * Converts an attribute value representing an xsd:boolean value to a
     * boolean using the rules as stated in the XML specification.
     *
     * @param lexicalXSDBoolean The string-value of the boolean
     * @return the boolean value represented by {@code lexicalXSDBoolean}
     * @throws java.lang.IllegalArgumentException When {@code lexicalXSDBoolean}
     * does fit the lexical space of the XSD boolean datatype
     */
    public static boolean parseBoolean(String lexicalXSDBoolean) {
        final boolean result;
        switch (lexicalXSDBoolean) {
            case "true":
            case "1":
                result = true;
                break;
            case "false":
            case "0":
                result = false;
                break;
            default:
                throw new IllegalArgumentException("'" + lexicalXSDBoolean + "' is not a valid xs:boolean value");
        }
        return result;
    }

    /**
     * Constructs a secure SAX Parser.
     *
     * @return a SAX Parser
     * @throws javax.xml.parsers.ParserConfigurationException thrown if there is
     * a parser configuration exception
     * @throws org.xml.sax.SAXNotRecognizedException thrown if there is an
     * unrecognized feature
     * @throws org.xml.sax.SAXNotSupportedException thrown if there is a
     * non-supported feature
     * @throws org.xml.sax.SAXException is thrown if there is a
     * org.xml.sax.SAXException
     */
    public static SAXParser buildSecureSaxParser() throws ParserConfigurationException,
            SAXNotRecognizedException, SAXNotSupportedException, SAXException {
        final SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return factory.newSAXParser();
    }

    /**
     * Constructs a new document builder with security features enabled.
     *
     * @return a new document builder
     * @throws javax.xml.parsers.ParserConfigurationException thrown if there is
     * a parser configuration exception
     */
    public static DocumentBuilder buildSecureDocumentBuilder() throws ParserConfigurationException {
        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        return factory.newDocumentBuilder();
    }

    /**
     * Builds a prettier exception message.
     *
     * @param ex the SAXParseException
     * @return an easier to read exception message
     */
    public static String getPrettyParseExceptionInfo(SAXParseException ex) {

        final StringBuilder sb = new StringBuilder();

        if (ex.getSystemId() != null) {
            sb.append("systemId=").append(ex.getSystemId()).append(", ");
        }
        if (ex.getPublicId() != null) {
            sb.append("publicId=").append(ex.getPublicId()).append(", ");
        }
        if (ex.getLineNumber() > 0) {
            sb.append("Line=").append(ex.getLineNumber());
        }
        if (ex.getColumnNumber() > 0) {
            sb.append(", Column=").append(ex.getColumnNumber());
        }
        sb.append(": ").append(ex.getMessage());

        return sb.toString();
    }
}
