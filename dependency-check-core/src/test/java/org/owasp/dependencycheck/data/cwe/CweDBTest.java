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
package org.owasp.dependencycheck.data.cwe;

import org.owasp.dependencycheck.data.cwe.CweDB;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class CweDBTest {

    public CweDBTest() {
    }

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
     * Method to serialize the CWE HashMap. This is not used in production; this
     * is only used once during dev to create the serialized HashMap.
     */
//    @Test
//    public void testUpdate() throws Exception {
//        SAXParserFactory factory = SAXParserFactory.newInstance();
//        SAXParser saxParser = factory.newSAXParser();
//
//        CweHandler handler = new CweHandler();
//        File file = new File(this.getClass().getClassLoader().getResource("cwe.2000.xml").getPath());
//
//        saxParser.parse(file, handler);
//        System.out.println("Found " + handler.getCwe().size() + " cwe entries.");
//        Map<String,String> cwe = handler.getCwe();
//        FileOutputStream fout = new FileOutputStream("src/main/resources/data/cwe.hashmap.serialized");
//        ObjectOutputStream objOut = new ObjectOutputStream(fout);
//        objOut.writeObject(cwe);
//        objOut.close();
//    }
    /**
     * Test of getCweName method, of class CweDB.
     */
    @Test
    public void testGetCweName() {
        String cweId = "CWE-16";
        String expResult = "Configuration";
        String result = CweDB.getCweName(cweId);
        assertEquals(expResult, result);
    }
}
