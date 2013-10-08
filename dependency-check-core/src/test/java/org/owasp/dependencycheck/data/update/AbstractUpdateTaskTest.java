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
import java.io.IOException;
import java.net.MalformedURLException;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;
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
public class AbstractUpdateTaskTest {

    public AbstractUpdateTaskTest() {
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

    public AbstractUpdateTask getAbstractUpdateImpl() throws Exception {
        DataStoreMetaInfo props = new DataStoreMetaInfo();
        AbstractUpdateTask instance = new AbstractUpdateImpl(props);
        return instance;
    }

    /**
     * Test of setDeleteAndRecreate method, of class AbstractUpdateTask.
     */
    @Test
    public void testSetDeleteAndRecreate() throws Exception {
        boolean deleteAndRecreate = false;
        boolean expResult = false;
        AbstractUpdateTask instance = getAbstractUpdateImpl();
        instance.setDeleteAndRecreate(deleteAndRecreate);
        boolean result = instance.shouldDeleteAndRecreate();
        assertEquals(expResult, result);
    }

    /**
     * Test of deleteExistingData method, of class AbstractUpdateTask.
     */
    @Test
    public void testDeleteExistingData() throws Exception {
        AbstractUpdateTask instance = getAbstractUpdateImpl();
        Exception result = null;
        try {
            instance.deleteExistingData();
        } catch (IOException ex) {
            result = ex;
        }
        assertNull(result);
    }

    /**
     * Test of openDataStores method, of class AbstractUpdateTask.
     */
    @Test
    public void testOpenDataStores() throws Exception {
        AbstractUpdateTask instance = getAbstractUpdateImpl();
        instance.openDataStores();
        instance.closeDataStores();
    }

    /**
     * Test of withinRange method, of class AbstractUpdateTask.
     */
    @Test
    public void testWithinRange() throws Exception {
        Calendar c = Calendar.getInstance();

        long current = c.getTimeInMillis();
        long lastRun = c.getTimeInMillis() - (3 * (1000 * 60 * 60 * 24));
        int range = 7; // 7 days
        AbstractUpdateTask instance = getAbstractUpdateImpl();
        boolean expResult = true;
        boolean result = instance.withinRange(lastRun, current, range);
        assertEquals(expResult, result);

        lastRun = c.getTimeInMillis() - (8 * (1000 * 60 * 60 * 24));
        expResult = false;
        result = instance.withinRange(lastRun, current, range);
        assertEquals(expResult, result);
    }

    public class AbstractUpdateImpl extends AbstractUpdateTask {

        public AbstractUpdateImpl(DataStoreMetaInfo props) throws Exception {
            super(props);
        }

        public Updateable updatesNeeded() throws MalformedURLException, DownloadFailedException, UpdateException {
            return null;
        }

        public void update() throws UpdateException {
        }
    }
}
