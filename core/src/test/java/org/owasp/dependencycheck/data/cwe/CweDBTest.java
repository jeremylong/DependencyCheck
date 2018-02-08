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

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long
 */
public class CweDBTest  extends BaseTest {

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
//        //File file = new File(this.getClass().getClassLoader().getResource("cwe.2000.xml").getPath());
//        File file = new File(this.getClass().getClassLoader().getResource("cwec_v2.5.xml").getPath());
//
//        saxParser.parse(file, handler);
//        System.out.println("Found " + handler.getCwe().size() + " cwe entries.");
//        Map<String, String> cwe = handler.getCwe();
////        FileOutputStream fout = new FileOutputStream("target/current.csv");
////        //FileOutputStream fout = new FileOutputStream("target/new.csv");
////        PrintWriter writer = new PrintWriter(fout);
////        for (Map.Entry<String, String> entry : cwe.entrySet()) {
////            writer.print('"');
////            writer.print(entry.getKey());
////            writer.print('"');
////            writer.print(',');
////            writer.print('"');
////            writer.print(entry.getValue());
////            writer.println('"');
////        }
////        writer.close();
//
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
