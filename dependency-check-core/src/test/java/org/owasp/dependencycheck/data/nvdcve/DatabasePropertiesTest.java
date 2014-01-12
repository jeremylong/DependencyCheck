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
package org.owasp.dependencycheck.data.nvdcve;

import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.update.NvdCveInfo;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DatabasePropertiesTest {

    public DatabasePropertiesTest() {
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
     * Test of isEmpty method, of class DatabaseProperties.
     */
    @Test
    public void testIsEmpty() throws Exception {
        CveDB cveDB = new CveDB();
        cveDB.open();
        DatabaseProperties instance = cveDB.getDatabaseProperties();
        boolean expResult = false;
        boolean result = instance.isEmpty();
        //no exception means the call worked... whether or not it is empty depends on if the db is new
        //assertEquals(expResult, result);
        cveDB.close();
    }

    /**
     * Test of save method, of class DatabaseProperties.
     */
    @Test
    public void testSave() throws Exception {
        NvdCveInfo updatedValue = new NvdCveInfo();
        String key = "test";
        long expected = 1337;
        updatedValue.setId(key);
        updatedValue.setTimestamp(expected);
        CveDB cveDB = new CveDB();
        cveDB.open();
        DatabaseProperties instance = cveDB.getDatabaseProperties();
        instance.save(updatedValue);
        //reload the properties
        cveDB.close();
        cveDB = new CveDB();
        cveDB.open();
        instance = cveDB.getDatabaseProperties();
        cveDB.close();
        long results = Long.parseLong(instance.getProperty("lastupdated." + key));
        assertEquals(expected, results);
    }

    /**
     * Test of getProperty method, of class DatabaseProperties.
     */
    @Test
    public void testGetProperty_String_String() throws Exception {
        String key = "doesn't exist";
        String defaultValue = "default";
        CveDB cveDB = new CveDB();
        cveDB.open();
        DatabaseProperties instance = cveDB.getDatabaseProperties();
        cveDB.close();
        String expResult = "default";
        String result = instance.getProperty(key, defaultValue);
        assertEquals(expResult, result);
    }
}
