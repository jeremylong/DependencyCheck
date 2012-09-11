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

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class DownloaderTest {

    public DownloaderTest() {
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

    
//This test is being removed because it is a bit too slow.
//    /**
//     * Test of fetchFile method, of class Downloader.
//     * @throws Exception thrown when an excpetion occurs.
//     */
//    @Test
//    public void testFetchFile_URL_String() throws Exception {
//        System.out.println("fetchFile");
//        
////        Settings.setString(Settings.KEYS.PROXY_URL, "test");
////        Settings.setString(Settings.KEYS.PROXY_PORT, "80");
////        Settings.setString(Settings.KEYS.CONNECTION_TIMEOUT, "1000");
//        
//        URL url = new URL(Settings.getString(Settings.KEYS.CPE_URL));
//        String outputPath = "target\\downloaded_cpe.xml";
//        Downloader.fetchFile(url, outputPath);
//    }
}
