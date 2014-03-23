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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

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

        key = "something that does not exist";
        expResult = true;
        result = Settings.getBoolean(key, true);
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
