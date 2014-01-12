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
public class UpdateableNvdCveTest {

    public UpdateableNvdCveTest() {
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

    /**
     * Test of isUpdateNeeded method, of class UpdateableNvdCve.
     */
    @Test
    public void testIsUpdateNeeded() throws MalformedURLException, DownloadFailedException, IOException {
        String id = "key";
        //use a local file as this test will load the result and check the timestamp
        File f = new File("target/test-classes/nvdcve-2.0-2012.xml");
        String url = "file:///" + f.getCanonicalPath();
        UpdateableNvdCve instance = new UpdateableNvdCve();
        instance.add(id, url, url, false);

        boolean expResult = false;
        boolean result = instance.isUpdateNeeded();
        assertEquals(expResult, result);

        instance.add("nextId", url, url, true);

        expResult = true;
        result = instance.isUpdateNeeded();
        assertEquals(expResult, result);
    }

    /**
     * Test of add method, of class UpdateableNvdCve.
     */
    @Test
    public void testAdd_3args() throws Exception {
        String id = "key";
        File f = new File("target/test-classes/nvdcve-2.0-2012.xml");
        //use a local file as this test will load the result and check the timestamp
        String url = "file:///" + f.getCanonicalPath();
        UpdateableNvdCve instance = new UpdateableNvdCve();
        instance.add(id, url, url);
        NvdCveInfo results = instance.get(id);
        assertEquals(id, results.getId());
        assertEquals(url, results.getUrl());
        assertEquals(url, results.getOldSchemaVersionUrl());
    }

    /**
     * Test of add method, of class UpdateableNvdCve.
     */
    @Test
    public void testAdd_4args() throws Exception {
        String id = "key";
        //use a local file as this test will load the result and check the timestamp
        File f = new File("target/test-classes/nvdcve-2.0-2012.xml");
        String url = "file:///" + f.getCanonicalPath();
        UpdateableNvdCve instance = new UpdateableNvdCve();
        instance.add(id, url, url, false);

        boolean expResult = false;
        boolean result = instance.isUpdateNeeded();
        assertEquals(expResult, result);

        instance.add("nextId", url, url, false);
        NvdCveInfo results = instance.get(id);

        assertEquals(id, results.getId());
        assertEquals(url, results.getUrl());
        assertEquals(url, results.getOldSchemaVersionUrl());

    }

    /**
     * Test of clear method, of class UpdateableNvdCve.
     */
    @Test
    public void testClear() throws MalformedURLException, DownloadFailedException, IOException {
        String id = "key";
        //use a local file as this test will load the result and check the timestamp
        File f = new File("target/test-classes/nvdcve-2.0-2012.xml");
        String url = "file:///" + f.getCanonicalPath();
        UpdateableNvdCve instance = new UpdateableNvdCve();
        instance.add(id, url, url, false);
        assertFalse(instance.getCollection().isEmpty());
        instance.clear();
        assertTrue(instance.getCollection().isEmpty());
    }

    /**
     * Test of iterator method, of class UpdatableNvdCve.
     */
    @Test
    public void testIterator() throws IOException {
        //use a local file as this test will load the result and check the timestamp
        File f = new File("target/test-classes/nvdcve-2.0-2012.xml");
        String url = "file:///" + f.getCanonicalPath();
        UpdateableNvdCve instance = new UpdateableNvdCve();
        instance.add("one", url, url, false);
        instance.add("two", url, url, false);
        instance.add("three", url, url, false);
        int itemsProcessed = 0;
        for (NvdCveInfo item : instance) {
            if ("one".equals(item.getId())) {
                instance.remove();
            }
            itemsProcessed += 1;
        }
        assertEquals(3, itemsProcessed);
        assertEquals(2, instance.getCollection().size());
    }
}
