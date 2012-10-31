package org.codesecure.dependencycheck.data.nvdcve.xml;
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

import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.index.CorruptIndexException;

/**
 * Imports a NVD CVE XML file into the Lucene NVD CVE Index.
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
     * Imports the NVD CVE XML File into the Lucene Index.
     *
     * @param file containing the path to the NVD CVE XML file.
     */
    public static void importXML(File file) {
        NvdCveParser indexer = null;
        try {

            indexer = new NvdCveParser();

            indexer.openIndexWriter();


            indexer.parse(file);

        } catch (CorruptIndexException ex) {
            Logger.getLogger(Importer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Importer.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (indexer != null) {
                indexer.close();
            }
        }
    }
//    public static void importXML(File file) throws FileNotFoundException, IOException, JAXBException,
//            ParserConfigurationException, SAXException {
//
//        SAXParserFactory factory = SAXParserFactory.newInstance();
//        factory.setNamespaceAware(true);
//        XMLReader reader = factory.newSAXParser().getXMLReader();
//
//        JAXBContext context = JAXBContext.newInstance("org.codesecure.dependencycheck.data.nvdcve.generated");
//        NvdCveXmlFilter filter = new NvdCveXmlFilter(context);
//
//        Indexer indexer = new Indexer();
//        indexer.openIndexWriter();
//
//        filter.registerSaveDelegate(indexer);
//
//        reader.setContentHandler(filter);
//        Reader fileReader = new FileReader(file);
//        InputSource is = new InputSource(fileReader);
//        try {
//            reader.parse(is);
//        } catch (IOException ex) {
//            Logger.getLogger(Importer.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (SAXException ex) {
//            Logger.getLogger(Importer.class.getName()).log(Level.SEVERE, null, ex);
//        } finally {
//            indexer.close();
//        }
//    }

    /**
     * Imports the CPE XML File into the Lucene Index.
     *
     * @param path the path to the CPE XML file.
     */
    public static void importXML(String path) {
        File f = new File(path);
        if (!f.exists()) {
            f.mkdirs();
        }
        Importer.importXML(f);
    }
}
