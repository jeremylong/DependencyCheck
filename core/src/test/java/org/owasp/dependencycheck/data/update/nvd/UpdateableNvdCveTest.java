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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.nvd;

import java.io.File;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long
 */
public class UpdateableNvdCveTest extends BaseTest {

    /**
     * Test of isUpdateNeeded method, of class UpdateableNvdCve.
     */
    @Test
    public void testIsUpdateNeeded() {
        String id = "key";
        String url = new File("target/test-classes/nvdcve-2.0-2012.xml").toURI().toString();
        long timestamp = 42;
        UpdateableNvdCve instance = new UpdateableNvdCve();
        instance.add(id, url, url, timestamp, false);

        boolean expResult = false;
        boolean result = instance.isUpdateNeeded();
        assertEquals(expResult, result);

        instance.add("nextId", url, url, 23, true);

        expResult = true;
        result = instance.isUpdateNeeded();
        assertEquals(expResult, result);
    }

    /**
     * Test of add method, of class UpdateableNvdCve.
     */
    @Test
    public void testAdd() throws Exception {
        String id = "key";
        String url = new File("target/test-classes/nvdcve-2.0-2012.xml").toURI().toString();
        long timestamp = 42;
        UpdateableNvdCve instance = new UpdateableNvdCve();
        instance.add(id, url, url, timestamp, false);

        boolean expResult = false;
        boolean result = instance.isUpdateNeeded();
        assertEquals(expResult, result);

        instance.add("nextId", url, url, 23, false);
        NvdCveInfo results = instance.get(id);

        assertEquals(id, results.getId());
        assertEquals(url, results.getUrl());
        assertEquals(url, results.getOldSchemaVersionUrl());
        assertEquals(timestamp, results.getTimestamp());
    }

    /**
     * Test of clear method, of class UpdateableNvdCve.
     */
    @Test
    public void testClear() {
        String id = "key";
        String url = new File("target/test-classes/nvdcve-2.0-2012.xml").toURI().toString();
        long timestamp = 42;
        UpdateableNvdCve instance = new UpdateableNvdCve();
        instance.add(id, url, url, timestamp, false);
        assertFalse(instance.getCollection().isEmpty());
        instance.clear();
        assertTrue(instance.getCollection().isEmpty());
    }

    /**
     * Test of iterator method, of class UpdatableNvdCve.
     */
    @Test
    public void testIterator() {
        String url = new File("target/test-classes/nvdcve-2.0-2012.xml").toURI().toString();
        UpdateableNvdCve instance = new UpdateableNvdCve();
        instance.add("one", url, url, 42, false);
        instance.add("two", url, url, 23, false);
        instance.add("three", url, url, 17, false);
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
