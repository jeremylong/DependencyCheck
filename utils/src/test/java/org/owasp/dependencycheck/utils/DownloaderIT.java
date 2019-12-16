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
import org.junit.Test;
import static org.junit.Assert.assertTrue;
import org.junit.Before;

/**
 *
 * @author Jeremy Long
 */
public class DownloaderIT extends BaseTest {

    /**
     * Initialize the {@link Settings}.
     */
    @Before
    @Override
    public void setUp() {
        super.setUp();
        applyHackFix();
    }

    /**
     * Test of fetchFile method, of class Downloader.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testFetchFile() throws Exception {

        URL url = new URL(getSettings().getString(Settings.KEYS.CVE_MODIFIED_JSON));
        File outputPath = new File("target/downloaded_cve.xml");
        Downloader downloader = new Downloader(getSettings());
        downloader.fetchFile(url, outputPath);
        assertTrue(outputPath.isFile());
    }

    /**
     * Upgrading to org.mock-server:mockserver-netty:5.8.0 caused this test case
     * to fail as netty does not allow TLSv1.3 to be "used" in Java 1.8. Under
     * 1.8 for some reason `https.protocols` includes TLSv1.3 even though it is
     * not supported in most implementations. Thus, we need to explicitly remove
     * it for this test case to work.
     */
    private void applyHackFix() {
        String httpProtocols = System.getProperty("https.protocols");
        if (httpProtocols != null && httpProtocols.contains(",TLSv1.3")) {
            httpProtocols = httpProtocols.replace(",TLSv1.3", "");
            System.setProperty("https.protocols", httpProtocols);
        } else if (httpProtocols != null && httpProtocols.contains("TLSv1.3,")) {
            httpProtocols = httpProtocols.replace("TLSv1.3,", "");
            System.setProperty("https.protocols", httpProtocols);
        }
    }
}
