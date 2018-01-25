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
import java.util.List;
import java.util.Map;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import static org.junit.Assert.assertFalse;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;

/**
 *
 * @author Jeremy Long
 */
public class NvdCve_1_2_HandlerTest  extends BaseTest {

    @Test
    public void testParse() throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser saxParser = factory.newSAXParser();

        //File file = new File(this.getClass().getClassLoader().getResource("nvdcve-2012.xml").getPath());
        File file = BaseTest.getResourceAsFile(this, "nvdcve-2012.xml");

        NvdCve12Handler instance = new NvdCve12Handler();
        saxParser.parse(file, instance);
        Map<String, List<VulnerableSoftware>> results = instance.getVulnerabilities();
        assertFalse("No vulnerable software identified with a previous version in 2012 CVE 1.2?", results.isEmpty());
    }
}
