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
package org.owasp.dependencycheck.data.update.nvd;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.xml.sax.SAXException;

/**
 *
 * @author Jeremy Long
 */
public class NvdCve_2_0_HandlerTest extends BaseTest {

    @Test
    public void testParse() {
        Throwable results = null;
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser saxParser = factory.newSAXParser();

            //File file = new File(this.getClass().getClassLoader().getResource("nvdcve-2.0-2012.xml").getPath());
            File file = BaseTest.getResourceAsFile(this, "nvdcve-2.0-2012.xml");

            NvdCve20Handler instance = new NvdCve20Handler();

            saxParser.parse(file, instance);
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            ex.printStackTrace();
            results = ex;
        }
        assertTrue("Exception thrown during parse of 2012 CVE version 2.0?", results == null);
        if (results != null) {
            System.err.println(results);
        }
    }

    @Test
    public void testParserWithPreviousVersion() {
        Throwable results = null;
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser saxParser = factory.newSAXParser();

            File file12 = BaseTest.getResourceAsFile(this, "cve-1.2-2008_4411.xml");
            
            final NvdCve12Handler cve12Handler = new NvdCve12Handler();
            saxParser.parse(file12, cve12Handler);
            final Map<String, List<VulnerableSoftware>> prevVersionVulnMap = cve12Handler.getVulnerabilities();

            //File file = new File(this.getClass().getClassLoader().getResource("nvdcve-2.0-2012.xml").getPath());
            File file20 = BaseTest.getResourceAsFile(this, "cve-2.0-2008_4411.xml");

            NvdCve20Handler instance = new NvdCve20Handler();
            instance.setPrevVersionVulnMap(prevVersionVulnMap);
            saxParser.parse(file20, instance);

            assertTrue(instance.getTotalNumberOfEntries()==1);            
        } catch (ParserConfigurationException | SAXException | IOException ex) {
            results = ex;
        }
        assertTrue("Exception thrown during parse of 2012 CVE version 2.0?", results == null);
        if (results != null) {
            System.err.println(results);
        }
    }
}
