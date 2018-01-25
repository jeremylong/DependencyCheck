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
package org.owasp.dependencycheck.utils;

import java.io.File;
import java.net.URL;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import static org.junit.Assert.assertTrue;

/**
 *
 * @author Jeremy Long
 */
public class DownloaderIT extends BaseTest {

    /**
     * Test of fetchFile method, of class Downloader.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testFetchFile() throws Exception {

//        Settings.setString(Settings.KEYS.CONNECTION_TIMEOUT, "1000");
//        Settings.setString(Settings.KEYS.PROXY_PORT, "8080");
//        Settings.setString(Settings.KEYS.PROXY_SERVER, "127.0.0.1");
        URL url = new URL(getSettings().getString(Settings.KEYS.CVE_MODIFIED_20_URL));
        File outputPath = new File("target/downloaded_cve.xml");
        Downloader downloader = new Downloader(getSettings());
        downloader.fetchFile(url, outputPath);
        assertTrue(outputPath.isFile());
    }

    @Test
    public void testGetLastModified() throws Exception {
        URL url = new URL(getSettings().getString(Settings.KEYS.CVE_MODIFIED_20_URL));
        Downloader downloader = new Downloader(getSettings());
        long timestamp = downloader.getLastModified(url);
        assertTrue("timestamp equal to zero?", timestamp > 0);
    }
}
