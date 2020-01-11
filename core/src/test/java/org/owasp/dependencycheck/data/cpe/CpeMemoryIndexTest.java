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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import org.apache.lucene.document.Document;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TopDocs;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.Engine;

/**
 *
 * @author jeremy long
 */
public class CpeMemoryIndexTest extends BaseDBTestCase {

    private static final CpeMemoryIndex instance = CpeMemoryIndex.getInstance();
    private static Engine engine = null;

    @AfterClass
    public static void tearDownClass() {
        if (instance.isOpen()) {
            instance.close();
        }
        if (engine != null) {
            engine.close();
        }
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        if (!instance.isOpen()) {
            engine = new Engine(getSettings());
            engine.openDatabase();
            instance.open(engine.getDatabase().getVendorProductList(), this.getSettings());
        }
    }

    /**
     * Test of getInstance method, of class CpeMemoryIndex.
     */
    @Test
    public void testGetInstance() {
        CpeMemoryIndex result = CpeMemoryIndex.getInstance();
        assertNotNull(result);
    }

    /**
     * Test of isOpen method, of class CpeMemoryIndex.
     */
    @Test
    public void testIsOpen() {
        boolean expResult = true;
        boolean result = instance.isOpen();
        assertEquals(expResult, result);
    }

    /**
     * Test of search method, of class CpeMemoryIndex.
     */
    @Test
    public void testSearch_String_int() throws Exception {
        String searchString = "product:(commons) AND vendor:(apache)";
        int maxQueryResults = 3;
        TopDocs result = instance.search(searchString, maxQueryResults);
        assertEquals(3, result.scoreDocs.length);
        instance.close();
    }

    /**
     * Test of parseQuery method, of class CpeMemoryIndex.
     */
    @Test
    public void testParseQuery() throws Exception {
        String searchString = "product:(resteasy) AND vendor:(red hat)";

        String expResult = "+product:resteasy +(vendor:red vendor:redhat vendor:hat)";
        Query result = instance.parseQuery(searchString);
        assertEquals(expResult, result.toString());
        instance.resetAnalyzers();
        searchString = "product:(struts2\\-core^2 struts^3 core) AND vendor:(apache.struts apache^3 foundation)";

        expResult = "+((product:struts2 product:struts2struts product:struts product:strutscore product:core)^2.0 (product:corestruts product:struts)^3.0 (product:strutscore product:core)) +((vendor:apache vendor:apachestruts vendor:struts) (vendor:strutsapache vendor:apache)^3.0)";
        result = instance.parseQuery(searchString);
        assertEquals(expResult, result.toString());
        instance.close();
    }

    /**
     * Test of search method, of class CpeMemoryIndex.
     */
    @Test
    public void testSearch_Query_int() throws Exception {
        String searchString = "product:(commons) AND vendor:(apache)";
        Query query = instance.parseQuery(searchString);
        int maxQueryResults = 3;
        TopDocs result = instance.search(query, maxQueryResults);
        assertEquals(3, result.scoreDocs.length);
    }

    /**
     * Test of getDocument method, of class CpeMemoryIndex.
     */
    @Test
    public void testGetDocument() throws Exception {
        String searchString = "product:(commons) AND vendor:(apache)";
        int maxQueryResults = 1;
        TopDocs docs = instance.search(searchString, maxQueryResults);
        int documentId = docs.scoreDocs[0].doc;
        Document result = instance.getDocument(documentId);
        assertEquals("apache", result.get("vendor"));
    }

    /**
     * Test of numDocs method, of class CpeMemoryIndex.
     */
    @Test
    public void testNumDocs() {
        int result = instance.numDocs();
        assertTrue(result > 100);
    }
}
