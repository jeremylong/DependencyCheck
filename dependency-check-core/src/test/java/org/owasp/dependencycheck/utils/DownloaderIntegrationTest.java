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
package org.owasp.dependencycheck.utils;

import java.io.File;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.Downloader;
import java.net.URL;
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
public class DownloaderIntegrationTest {

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
     * Test of fetchFile method, of class Downloader.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testFetchFile() throws Exception {

//        Settings.setString(Settings.KEYS.CONNECTION_TIMEOUT, "1000");
//        Settings.setString(Settings.KEYS.PROXY_PORT, "8080");
//        Settings.setString(Settings.KEYS.PROXY_URL, "127.0.0.1");

        URL url = new URL(Settings.getString(Settings.KEYS.CVE_MODIFIED_20_URL));
        File outputPath = new File("target/downloaded_cve.xml");
        Downloader.fetchFile(url, outputPath);

    }

    @Test
    public void testGetLastModified() throws Exception {
        URL url = new URL("http://nvd.nist.gov/download/nvdcve-2012.xml");
        long timestamp = Downloader.getLastModified(url);
        assertTrue("timestamp equal to zero?", timestamp > 0);
    }
}
