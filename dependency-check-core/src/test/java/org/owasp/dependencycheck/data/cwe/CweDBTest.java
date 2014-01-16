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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cwe;

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

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
     * Method to serialize the CWE HashMap. This is not used in production; this is only used once during dev to create
     * the serialized HashMap.
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
