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
package org.owasp.dependencycheck.utils;

import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class SettingsTest {

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    /**
     * Test of getString method, of class Settings.
     */
    @Test
    public void testGetString() {
        String key = Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS;
        String expResult = "7";
        String result = Settings.getString(key);
        Assert.assertTrue(result.endsWith(expResult));
    }

    /**
     * Test of getDataFile method, of class Settings.
     */
    @Test
    public void testGetDataFile() throws IOException {
        String key = Settings.KEYS.DATA_DIRECTORY;
        String expResult = "data";
        File result = Settings.getDataFile(key);
        Assert.assertTrue(result.getAbsolutePath().endsWith(expResult));
    }

    /**
     * Test of mergeProperties method, of class Settings.
     */
    @Test
    public void testMergeProperties_String() throws IOException, URISyntaxException {
        String key = Settings.KEYS.PROXY_PORT;
        String expResult = Settings.getString(key);
        File f = new File(this.getClass().getClassLoader().getResource("test.properties").toURI());
        //InputStream in = this.getClass().getClassLoader().getResourceAsStream("test.properties");
        Settings.mergeProperties(f.getAbsolutePath());
        String result = Settings.getString(key);
        Assert.assertTrue("setting didn't change?", (expResult == null && result != null) || !expResult.equals(result));
    }

    /**
     * Test of setString method, of class Settings.
     */
    @Test
    public void testSetString() {
        String key = "newProperty";
        String value = "someValue";
        Settings.setString(key, value);
        String expResults = Settings.getString(key);
        Assert.assertEquals(expResults, value);
    }

    /**
     * Test of getString method, of class Settings.
     */
    @Test
    public void testGetString_String_String() {
        String key = "key That Doesn't Exist";
        String defaultValue = "blue bunny";
        String expResult = "blue bunny";
        String result = Settings.getString(key);
        Assert.assertTrue(result == null);
        result = Settings.getString(key, defaultValue);
        Assert.assertEquals(expResult, result);
    }

    /**
     * Test of getString method, of class Settings.
     */
    @Test
    public void testGetString_String() {
        String key = Settings.KEYS.CONNECTION_TIMEOUT;
        String result = Settings.getString(key);
        Assert.assertTrue(result == null);
    }

    /**
     * Test of getInt method, of class Settings.
     */
    @Test
    public void testGetInt() throws InvalidSettingException {
        String key = "SomeNumber";
        int expResult = 85;
        Settings.setString(key, "85");
        int result = Settings.getInt(key);
        Assert.assertEquals(expResult, result);
    }

    /**
     * Test of getLong method, of class Settings.
     */
    @Test
    public void testGetLong() throws InvalidSettingException {
        String key = "SomeNumber";
        long expResult = 300L;
        Settings.setString(key, "300");
        long result = Settings.getLong(key);
        Assert.assertEquals(expResult, result);
    }

    /**
     * Test of getBoolean method, of class Settings.
     */
    @Test
    public void testGetBoolean() throws InvalidSettingException {
        String key = "SomeBoolean";
        Settings.setString(key, "false");
        boolean expResult = false;
        boolean result = Settings.getBoolean(key);
        Assert.assertEquals(expResult, result);
    }

    /**
     * Test of removeProperty method, of class Settings.
     */
    @Test
    public void testRemoveProperty() {
        String key = "SomeKey";
        String value = "value";
        String dfault = "default";
        Settings.setString(key, value);
        String ret = Settings.getString(key);
        Assert.assertEquals(value, ret);
        Settings.removeProperty(key);
        ret = Settings.getString(key, dfault);
        Assert.assertEquals(dfault, ret);
    }
}
