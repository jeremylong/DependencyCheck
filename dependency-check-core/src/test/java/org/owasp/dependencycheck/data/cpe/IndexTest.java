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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import org.owasp.dependencycheck.data.cpe.Index;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.document.Document;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class IndexTest {

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of open method, of class Index.
     */
    @Test
    public void testOpen() {
        Index instance = new Index();
        try {
            instance.open();
            //TODO research why are we getting multiple documents for the same documentId. is the update method not working?
//            try {
//                instance.createSearchingAnalyzer();
//                TopDocs docs = instance.search("product:( project\\-open )", 20);
//                for (ScoreDoc d : docs.scoreDocs) {
//                    final Document doc = instance.getDocument(d.doc);
//                    String vendor = doc.getField(Fields.VENDOR).stringValue();
//                    String product = doc.getField(Fields.PRODUCT).stringValue();
//                    System.out.print(d.doc);
//                    System.out.print(" : ");
//                    System.out.print(vendor + ":");
//                    System.out.println(product);
//                }
//            } catch (ParseException ex) {
//                Logger.getLogger(IndexTest.class.getName()).log(Level.SEVERE, null, ex);
//            }
        } catch (IOException ex) {
            assertNull(ex.getMessage(), ex);
        }
        instance.close();
    }

    /**
     * Test of getDirectory method, of class Index.
     *
     * @throws Exception
     */
    @Test
    public void testGetDirectory() throws Exception {
        Index index = new Index();
        Directory result = index.getDirectory();

        String exp = File.separatorChar + "target" + File.separatorChar + "data" + File.separatorChar + "cpe";
        assertTrue(result.toString().contains(exp));
    }
}
