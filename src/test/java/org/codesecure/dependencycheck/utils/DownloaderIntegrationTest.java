/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.utils;

import java.net.URL;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class DownloaderIntegrationTest {

    public DownloaderIntegrationTest() {
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
     * Test of fetchFile method, of class Downloader.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testFetchFile() throws Exception {
        System.out.println("fetchFile");

//        Settings.setString(Settings.KEYS.CONNECTION_TIMEOUT, "1000");

//        Settings.setString(Settings.KEYS.PROXY_PORT, "8080");
//        Settings.setString(Settings.KEYS.PROXY_URL, "127.0.0.1");

        URL url = new URL(Settings.getString(Settings.KEYS.CPE_URL));
        String outputPath = "target\\downloaded_cpe.xml";
        Downloader.fetchFile(url, outputPath, true);

        url = new URL("http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml");
        outputPath = "target\\downloaded_cve.xml";
        Downloader.fetchFile(url, outputPath, false);

    }
    
    @Test
    public void testGetLastModified() throws Exception {
        System.out.println("getLastModified");
        URL url = new URL("http://nvd.nist.gov/download/nvdcve-2012.xml");
        long timestamp = Downloader.getLastModified(url);
        assertTrue("timestamp equal to zero?", timestamp>0);
    }
}
