/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.utils;

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
        String expResult = "target/store/cpe";
        String result = Settings.getString(key);
        assertTrue(result.endsWith(expResult));
    }
}
