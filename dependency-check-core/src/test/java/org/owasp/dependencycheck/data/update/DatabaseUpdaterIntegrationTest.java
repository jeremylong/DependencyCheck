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
package org.owasp.dependencycheck.data.update;

import java.io.File;
import java.net.URL;
import org.owasp.dependencycheck.data.update.DatabaseUpdater;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class DatabaseUpdaterIntegrationTest {

    public DatabaseUpdaterIntegrationTest() {
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
     * Test of update method, of class DatabaseUpdater.
     *
     * @throws Exception
     */
    @Test
    public void testUpdate() throws Exception {
        DatabaseUpdater instance = new DatabaseUpdater();
        instance.update();
    }

    /**
     * Test of update method (when in batch mode), of class DatabaseUpdater.
     *
     * @throws Exception
     */
    @Test
    public void testBatchUpdate() throws Exception {
        File file = new File(this.getClass().getClassLoader().getResource("data.zip").toURI());
        String path = "file:///" + file.getCanonicalPath();
        Settings.setString(Settings.KEYS.BATCH_UPDATE_URL, path);
        DatabaseUpdater instance = new DatabaseUpdater();
        instance.update();
        Settings.setString(Settings.KEYS.BATCH_UPDATE_URL, "");
    }
}
