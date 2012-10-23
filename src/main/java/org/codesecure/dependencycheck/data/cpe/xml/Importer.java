package org.codesecure.dependencycheck.data.cpe.xml;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.apache.lucene.index.CorruptIndexException;
import org.xml.sax.SAXException;

/**
 * Imports a CPE XML file into the Lucene CPE Index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Importer {

    /**
     * Private constructor for utility class.
     */
    private Importer() {
    }

    /**
     * Imports the CPE XML File into the Lucene Index.
     *
     * @param file containing the path to the CPE XML file.
     * @throws ParserConfigurationException is thrown if the parser is
     * misconfigured.
     * @throws SAXException is thrown when there is a SAXException.
     * @throws IOException is thrown when there is an IOException.
     * @throws CorruptIndexException is thrown when the Lucene index is corrupt.
     */
    public static void importXML(File file) throws CorruptIndexException, ParserConfigurationException, IOException, SAXException {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser saxParser = factory.newSAXParser();
        CPEHandler handler = new CPEHandler();
        Indexer indexer = new Indexer();
        indexer.openIndexWriter();
        handler.registerSaveDelegate(indexer);
        try {
            saxParser.parse(file, handler);
        } catch (SAXException ex) {
            Logger.getLogger(Importer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Importer.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            indexer.close();
        }
    }

    /**
     * Imports the CPE XML File into the Lucene Index.
     *
     * @param path the path to the CPE XML file.
     * @throws ParserConfigurationException is thrown if the parser is
     * misconfigured.
     * @throws SAXException is thrown when there is a SAXException.
     * @throws IOException is thrown when there is an IOException.
     */
    public static void importXML(String path) throws ParserConfigurationException, SAXException, IOException {
        File f = new File(path);
        if (!f.exists()) {
            f.mkdirs();
        }
        Importer.importXML(f);
    }
}
