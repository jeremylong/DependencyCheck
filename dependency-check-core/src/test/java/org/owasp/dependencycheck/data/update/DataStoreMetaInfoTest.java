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
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class DataStoreMetaInfoTest {

    public DataStoreMetaInfoTest() {
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
     * Test of isEmpty method, of class DataStoreMetaInfo.
     */
    @Test
    public void testIsEmpty() {
        DataStoreMetaInfo instance = new DataStoreMetaInfo();
        boolean expResult = false;
        boolean result = instance.isEmpty();
        assertEquals(expResult, result);
    }

    /**
     * Test of save method, of class DataStoreMetaInfo.
     */
    @Test
    public void testSave() throws Exception {
        NvdCveInfo updatedValue = new NvdCveInfo();
        String key = "test";
        long expected = 1337;
        updatedValue.setId(key);
        updatedValue.setTimestamp(expected);
        DataStoreMetaInfo instance = new DataStoreMetaInfo();
        instance.save(updatedValue);
        //reload the properties
        instance = new DataStoreMetaInfo();
        long results = Long.parseLong(instance.getProperty("lastupdated." + key));
        assertEquals(expected, results);

    }

    /**
     * Test of getProperty method, of class DataStoreMetaInfo.
     */
    @Test
    public void testGetProperty_String_String() {
        String key = "doesn't exist";
        String defaultValue = "default";
        DataStoreMetaInfo instance = new DataStoreMetaInfo();
        String expResult = "default";
        String result = instance.getProperty(key, defaultValue);
        assertEquals(expResult, result);
    }

    /**
     * Test of getPropertiesFile method, of class DataStoreMetaInfo.
     */
    @Test
    public void testGetPropertiesFile() {
        File result = DataStoreMetaInfo.getPropertiesFile();
        //wow... rigorous!
        assertNotNull(result);
    }
}
