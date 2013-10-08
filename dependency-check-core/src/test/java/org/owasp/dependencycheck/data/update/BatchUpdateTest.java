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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import java.io.File;
import java.net.MalformedURLException;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class BatchUpdateTest {

    public BatchUpdateTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }
    private String old12;
    private String old20;

    @Before
    public void setUp() throws Exception {
        old12 = Settings.getString(Settings.KEYS.CVE_MODIFIED_12_URL);
        old20 = Settings.getString(Settings.KEYS.CVE_MODIFIED_20_URL);

        File tmp = Settings.getTempDirectory();
        if (!tmp.exists()) {
            tmp.mkdirs();
        }

        File dest = new File(tmp, "data.zip");
        File file = new File(this.getClass().getClassLoader().getResource("data.zip").toURI());
        FileUtils.copyFile(file, dest);
        String path = "file:///" + dest.getCanonicalPath();
        Settings.setString(Settings.KEYS.BATCH_UPDATE_URL, path);

        dest = new File(tmp, "nvdcve-2012.xml");
        file = new File(this.getClass().getClassLoader().getResource("nvdcve-2012.xml").toURI());
        FileUtils.copyFile(file, dest);
        path = "file:///" + dest.getCanonicalPath();
        Settings.setString(Settings.KEYS.CVE_MODIFIED_12_URL, path);

        dest = new File(tmp, "nvdcve-2.0-2012.xml");
        file = new File(this.getClass().getClassLoader().getResource("nvdcve-2.0-2012.xml").toURI());
        FileUtils.copyFile(file, dest);
        path = "file:///" + dest.getCanonicalPath();
        Settings.setString(Settings.KEYS.CVE_MODIFIED_20_URL, path);
    }

    @After
    public void tearDown() {
        Settings.setString(Settings.KEYS.CVE_MODIFIED_12_URL, old12);
        Settings.setString(Settings.KEYS.CVE_MODIFIED_20_URL, old20);
        Settings.setString(Settings.KEYS.BATCH_UPDATE_URL, "");
    }

    /**
     * Test of setDoBatchUpdate method, of class BatchUpdate.
     */
    @Test
    public void testSetDoBatchUpdate() throws DownloadFailedException, MalformedURLException, UpdateException {
        boolean expected = false;
        BatchUpdate instance = new BatchUpdate();
        instance.setDoBatchUpdate(expected);
        boolean results = instance.isDoBatchUpdate();
        assertEquals(results, expected);
    }

    /**
     * Test of update method, of class BatchUpdate.
     */
    @Test
    public void testUpdate() throws Exception {
        BatchUpdate instance = new BatchUpdate();

        //do some setup
        instance.setDoBatchUpdate(true);
        instance.deleteExistingData();

        instance.update(); //no exceptions it worked?
        //todo add some actual asserts to check things.
    }
}
