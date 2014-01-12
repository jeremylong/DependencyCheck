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

import org.owasp.dependencycheck.data.update.exception.UpdateException;

import java.net.MalformedURLException;
import java.util.Calendar;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.utils.DownloadFailedException;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class StandardUpdateIntegrationTest {

    public StandardUpdateIntegrationTest() {
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

    public StandardUpdate getStandardUpdateTask() throws MalformedURLException, DownloadFailedException, UpdateException {
        StandardUpdate instance = new StandardUpdate();
        return instance;
    }

    /**
     * Test of openDataStores method, of class StandardUpdate.
     */
    @Test
    public void testOpenDataStores() throws Exception {
        StandardUpdate instance = getStandardUpdateTask();
        instance.openDataStores();
        instance.closeDataStores();
    }

    /**
     * Test of withinRange method, of class StandardUpdate.
     */
    @Test
    public void testWithinRange() throws Exception {
        Calendar c = Calendar.getInstance();

        long current = c.getTimeInMillis();
        long lastRun = c.getTimeInMillis() - (3 * (1000 * 60 * 60 * 24));
        int range = 7; // 7 days
        StandardUpdate instance = getStandardUpdateTask();
        boolean expResult = true;
        boolean result = instance.withinRange(lastRun, current, range);
        assertEquals(expResult, result);

        lastRun = c.getTimeInMillis() - (8 * (1000 * 60 * 60 * 24));
        expResult = false;
        result = instance.withinRange(lastRun, current, range);
        assertEquals(expResult, result);
    }

    /**
     * Test of update method, of class StandardUpdate.
     */
    @Test
    public void testUpdate() throws Exception {
        StandardUpdate instance = getStandardUpdateTask();
        instance.update();
        //TODO make this an actual test
    }

    /**
     * Test of updatesNeeded method, of class StandardUpdate.
     */
    @Test
    public void testUpdatesNeeded() throws Exception {
        StandardUpdate instance = getStandardUpdateTask();
        UpdateableNvdCve result = instance.updatesNeeded();
        assertNotNull(result);
    }
}
