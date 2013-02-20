/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.utils;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import junit.framework.TestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author jeremy
 */
public class SettingsTest {

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
        System.out.println("getString");
        String key = Settings.KEYS.CPE_INDEX;
        String expResult = "target/data/cpe";
        String result = Settings.getString(key);
        Assert.assertTrue(result.endsWith(expResult));
    }

    /**
     * Test of mergeProperties method, of class Settings.
     */
    @Test
    public void testMergeProperties_String() throws IOException, URISyntaxException {
        System.out.println("getString");
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
        System.out.println("setString");
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
        System.out.println("getString");
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
        System.out.println("getString");
        String key = Settings.KEYS.CONNECTION_TIMEOUT;
        String result = Settings.getString(key);
        Assert.assertTrue(result == null);
    }

    /**
     * Test of getInt method, of class Settings.
     */
    @Test
    public void testGetInt() throws InvalidSettingException {
        System.out.println("getInt");
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
        System.out.println("getLong");
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
        System.out.println("getBoolean");
        String key = "SomeBoolean";
        Settings.setString(key, "false");
        boolean expResult = false;
        boolean result = Settings.getBoolean(key);
        Assert.assertEquals(expResult, result);
    }
}
