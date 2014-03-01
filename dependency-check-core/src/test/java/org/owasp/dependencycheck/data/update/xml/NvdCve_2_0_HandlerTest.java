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
package org.owasp.dependencycheck.data.update.xml;

import java.io.File;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NvdCve_2_0_HandlerTest {

    public NvdCve_2_0_HandlerTest() {
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

    @Test
    public void testParse() {
        Throwable results = null;
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser saxParser = factory.newSAXParser();

            File file = new File(this.getClass().getClassLoader().getResource("nvdcve-2.0-2012.xml").getPath());

            NvdCve20Handler instance = new NvdCve20Handler();

            saxParser.parse(file, instance);
        } catch (Throwable ex) {
            results = ex;
        }
        assertTrue("Exception thrown during parse of 2012 CVE version 2.0?", results == null);
        if (results != null) {
            System.err.println(results);
        }

    }
}
