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
package org.owasp.dependencycheck.data.nvdcve;

import org.owasp.dependencycheck.BaseDBTestCase;
import java.util.Properties;
import org.junit.After;
import org.junit.Test;
import org.owasp.dependencycheck.data.update.nvd.NvdCveInfo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;

/**
 *
 * @author Jeremy Long
 */
public class DatabasePropertiesIT extends BaseDBTestCase {

    private CveDB cveDb = null;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        cveDb = new CveDB(getSettings());
        cveDb.open();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        cveDb.close();
        super.tearDown();
    }

    /**
     * Test of isEmpty method, of class DatabaseProperties.
     */
    @Test
    public void testIsEmpty() throws Exception {
        DatabaseProperties prop = cveDb.getDatabaseProperties();
        assertNotNull(prop);
        //no exception means the call worked... whether or not it is empty depends on if the db is new
        //assertEquals(expResult, result);
    }

    /**
     * Test of save method, of class DatabaseProperties.
     */
    @Test
    public void testSave() throws Exception {
        NvdCveInfo updatedValue = new NvdCveInfo("test","url",1337L);
        String key = "test";
        long expected = 1337L;
        DatabaseProperties instance = cveDb.getDatabaseProperties();
        instance.save(updatedValue);
        instance = cveDb.reloadProperties();
        long results = Long.parseLong(instance.getProperty("NVD CVE " + key));
        assertEquals(expected, results);
    }

    /**
     * Test of getProperty method, of class DatabaseProperties.
     */
    @Test
    public void testGetProperty_String_String() throws Exception {
        String key = "doesn't exist";
        String defaultValue = "default";
        DatabaseProperties instance = cveDb.getDatabaseProperties();
        String expResult = "default";
        String result = instance.getProperty(key, defaultValue);
        assertEquals(expResult, result);
    }

    /**
     * Test of getProperty method, of class DatabaseProperties.
     */
    @Test
    public void testGetProperty_String() throws DatabaseException {
        String key = "version";
        DatabaseProperties instance = cveDb.getDatabaseProperties();
        String result = instance.getProperty(key);
        double version = Double.parseDouble(result);
        assertTrue(version >= 2.8);
        assertTrue(version <= 10);
    }

    /**
     * Test of getProperties method, of class DatabaseProperties.
     */
    @Test
    public void testGetProperties() throws DatabaseException {
        DatabaseProperties instance = cveDb.getDatabaseProperties();
        Properties result = instance.getProperties();
        assertTrue(result.size() > 0);
        cveDb.close();
    }
}
