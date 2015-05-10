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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.pom;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * A parser for pom.xml files.
 *
 * @author Jeremy Long
 */
public class PomParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(PomParser.class.getName());

    /**
     * Parses the given xml file and returns a Model object containing only the fields dependency-check requires.
     *
     * @param file a pom.xml
     * @return a Model object containing only the fields dependency-check requires
     * @throws PomParseException thrown if the xml file cannot be parsed
     */
    public Model parse(File file) throws PomParseException {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            return parse(fis);
        } catch (IOException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new PomParseException(ex);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.FINE, "Unable to close stream", ex);
                }
            }
        }
    }

    /**
     * Parses the given XML file and returns a Model object containing only the fields dependency-check requires.
     *
     * @param inputStream an InputStream containing suppression rues
     * @return a list of suppression rules
     * @throws PomParseException if the XML cannot be parsed
     */
    public Model parse(InputStream inputStream) throws PomParseException {
        try {
            final PomHandler handler = new PomHandler();
            final SAXParserFactory factory = SAXParserFactory.newInstance();
//            factory.setNamespaceAware(true);
//            factory.setValidating(true);
            final SAXParser saxParser = factory.newSAXParser();
            final XMLReader xmlReader = saxParser.getXMLReader();
            xmlReader.setContentHandler(handler);

            final Reader reader = new InputStreamReader(inputStream, "UTF-8");
            final InputSource in = new InputSource(reader);
            //in.setEncoding("UTF-8");

            xmlReader.parse(in);

            return handler.getModel();
        } catch (ParserConfigurationException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new PomParseException(ex);
        } catch (SAXException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new PomParseException(ex);
        } catch (FileNotFoundException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new PomParseException(ex);
        } catch (IOException ex) {
            LOGGER.log(Level.FINE, null, ex);
            throw new PomParseException(ex);
        }
    }
}
