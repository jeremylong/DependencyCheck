/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import junit.framework.TestCase;
import org.junit.Test;

/**
 *
 * @author jeremy
 */
public class SettingsTest extends TestCase {

    public SettingsTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
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
        assertTrue(result.endsWith(expResult));
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
        assertTrue("setting didn't change?", (expResult == null && result != null) || !expResult.equals(result));
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
        assertEquals(expResults, value);
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
        assertTrue(result == null);
        result = Settings.getString(key, defaultValue);
        assertEquals(expResult, result);
    }

    /**
     * Test of getString method, of class Settings.
     */
    @Test
    public void testGetString_String() {
        System.out.println("getString");
        String key = Settings.KEYS.CONNECTION_TIMEOUT;
        String result = Settings.getString(key);
        assertTrue(result == null);
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
        assertEquals(expResult, result);
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
        assertEquals(expResult, result);
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
        assertEquals(expResult, result);
    }
}
