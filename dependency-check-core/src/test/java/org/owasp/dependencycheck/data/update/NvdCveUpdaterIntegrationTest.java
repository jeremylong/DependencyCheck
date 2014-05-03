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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import java.io.File;
import java.util.Calendar;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NvdCveUpdaterIntegrationTest extends BaseTest {

    @Before
    public void setUp() throws Exception {
        int year = Calendar.getInstance().get(Calendar.YEAR);
        if (year <= 2014) {
            File f = new File(NvdCveUpdaterIntegrationTest.class.getClassLoader().getResource("nvdcve-2.0-2014.xml").getPath());
            String baseURL = f.toURI().toURL().toString();
            String modified12 = baseURL.replace("nvdcve-2.0-2014.xml", "nvdcve-modified.xml");
            String modified20 = baseURL.replace("nvdcve-2.0-2014.xml", "nvdcve-2.0-modified.xml");
            String full12 = baseURL.replace("nvdcve-2.0-2014.xml", "nvdcve-%d.xml");
            String full20 = baseURL.replace("nvdcve-2.0-2014.xml", "nvdcve-2.0-%d.xml");
//        cve.url-1.2.modified=http://nvd.nist.gov/download/nvdcve-modified.xml
//        cve.url-2.0.modified=http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml
//        cve.startyear=2014
//        cve.url-2.0.base=http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml
//        cve.url-1.2.base=http://nvd.nist.gov/download/nvdcve-%d.xml

            Settings.setString(Settings.KEYS.CVE_MODIFIED_12_URL, modified12);
            Settings.setString(Settings.KEYS.CVE_MODIFIED_20_URL, modified20);
            Settings.setString(Settings.KEYS.CVE_SCHEMA_1_2, full12);
            Settings.setString(Settings.KEYS.CVE_SCHEMA_2_0, full20);
            Settings.setString(Settings.KEYS.CVE_START_YEAR, "2014");
        } else {
            System.err.println("Consider updating the local data files to make the NvdCveUpdaterIntegrationTest perform faster");
        }
    }

    /**
     * Test of update method, of class NvdCveUpdater.
     */
    @Test
    public void testUpdate() throws Exception {
        NvdCveUpdater instance = new NvdCveUpdater();
        instance.update();
    }
}
