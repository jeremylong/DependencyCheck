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

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Jeremy Long
 */
public class SettingsTest extends BaseTest {

    /**
     * Initialize the {@link Settings} singleton.
     */
    @Before
    public void setUp() {
        Settings.initialize();
    }

    /**
     * Clean the {@link Settings} singleton.
     */
    @After
    public void tearDown() {
        Settings.cleanup();
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
     * Test of setStringIfNotNull method, of class Settings.
     */
    @Test
    public void testSetStringIfNotNull() {
        String key = "nullableProperty";
        String value = "someValue";
        Settings.setString(key, value);
        Settings.setStringIfNotNull(key, null); // NO-OP
        String expResults = Settings.getString(key);
        Assert.assertEquals(expResults, value);
    }

    /**
     * Test of setStringIfNotNull method, of class Settings.
     */
    @Test
    public void testSetStringIfNotEmpty() {
        String key = "optionalProperty";
        String value = "someValue";
        Settings.setString(key, value);
        Settings.setStringIfNotEmpty(key, ""); // NO-OP
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
     * Test of getInt method, of class Settings.
     */
    @Test
    public void testGetIntDefault() throws InvalidSettingException {
        String key = "SomeKey";
        int expResult = 85;
        Settings.setString(key, "blue");
        int result = Settings.getInt(key, expResult);
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

    /**
     * Test of getConnectionString.
     */
    @Test
    public void testGetConnectionString() throws Exception {
        String value = Settings.getConnectionString(Settings.KEYS.DB_CONNECTION_STRING, Settings.KEYS.DB_FILE_NAME);
        Assert.assertNotNull(value);
        String msg = null;
        try {
            value = Settings.getConnectionString("invalidKey", null);
        } catch (InvalidSettingException e) {
            msg = e.getMessage();
        }
        Assert.assertNotNull(msg);
    }

    /**
     * Test of getTempDirectory.
     */
    @Test
    public void testGetTempDirectory() throws Exception {
        File tmp = Settings.getTempDirectory();
        Assert.assertTrue(tmp.exists());
    }

    /**
     * Assert {@link Settings#getArray(String)} from a delimited string returns
     * multiple values in an array.
     */
    @Test
    public void testGetArrayFromADelimitedString() {
        // GIVEN a delimited string
        final String delimitedString = "value1,value2";
        Settings.setString("key", delimitedString);

        // WHEN getting the array
        final String[] array = Settings.getArray("key");

        // THEN the split array is returned
        assertThat("Expected the array to be non-null", array, notNullValue());
        assertThat("Expected the array to have two values", array.length, is(2));
        assertThat("Expected the first array value to be value1", array[0], is("value1"));
        assertThat("Expected the second array value to be value2", array[1], is("value2"));
    }

    /**
     * Assert {@link Settings#getArray(String)} returns {@code null} if the
     * property is not set.
     */
    @Test
    public void testGetArrayWhereThePropertyIsNotSet() {
        // WHEN getting the array
        final String[] array = Settings.getArray("key");

        // THEN null is returned
        assertThat("Expected the array to be null", array, nullValue());
    }

    /**
     * Assert {@link Settings#setArrayIfNotEmpty(String, String[])} with an
     * empty array is ignored.
     */
    @Test
    public void testSetArrayNotEmptyIgnoresAnEmptyArray() {
        // GIVEN an empty array
        final String[] array = {};

        // WHEN setting the array
        Settings.setArrayIfNotEmpty("key", array);

        // THEN the property was not set
        assertThat("Expected the property to not be set", Settings.getString("key"), nullValue());
    }

    /**
     * Assert {@link Settings#setArrayIfNotEmpty(String, String[])} with a null
     * array is ignored.
     */
    @Test
    public void testSetArrayNotEmptyIgnoresAnNullArray() {
        // GIVEN a null array
        final String[] array = null;

        // WHEN setting the array
        Settings.setArrayIfNotEmpty("key", array);

        // THEN the property was not set
        assertThat("Expected the property to not be set", Settings.getString("key"), nullValue());
    }

    /**
     * Assert {@link Settings#setArrayIfNotEmpty(String, String[])} with
     * multiple values sets a delimited string.
     */
    @Test
    public void testSetArrayNotEmptySetsADelimitedString() {
        // GIVEN an array with values
        final String[] array = {"value1", "value2"};

        // WHEN setting the array
        Settings.setArrayIfNotEmpty("key", array);

        // THEN the property is set
        assertThat("Expected the property to be set", Settings.getString("key"), is("value1,value2"));
    }

    /**
     * Assert {@link Settings#setArrayIfNotEmpty(String, String[])} with a
     * single values sets a string.
     */
    @Test
    public void testSetArrayNotEmptyWithSingleValueSetsAString() {
        // GIVEN an array with a value
        final String[] array = {"value1"};

        // WHEN setting the array
        Settings.setArrayIfNotEmpty("key", array);

        // THEN the property is set
        assertThat("Expected the property to be set", Settings.getString("key"), is("value1"));
    }
}
