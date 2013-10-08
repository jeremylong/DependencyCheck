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

import java.net.MalformedURLException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.utils.DownloadFailedException;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class StandardUpdateTaskIntegrationTest {

    public StandardUpdateTaskIntegrationTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    public StandardUpdateTask getStandardUpdateTask() throws MalformedURLException, DownloadFailedException, UpdateException {
        DataStoreMetaInfo props = new DataStoreMetaInfo();
        StandardUpdateTask instance = new StandardUpdateTask(props);
        return instance;
    }

    /**
     * Test of update method, of class StandardUpdateTask.
     */
    @Test
    public void testUpdate() throws Exception {
        StandardUpdateTask instance = getStandardUpdateTask();
        instance.update();
        //TODO make this an actual test
    }

    /**
     * Test of updatesNeeded method, of class StandardUpdateTask.
     */
    @Test
    public void testUpdatesNeeded() throws Exception {
        StandardUpdateTask instance = getStandardUpdateTask();
        Updateable result = instance.updatesNeeded();
        assertNotNull(result);
    }
}
