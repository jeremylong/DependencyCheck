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

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Rigorous test of setters/getters.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NvdCveInfoTest {

    public NvdCveInfoTest() {
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
     * Test of setId and getId method, of class NvdCveInfo.
     */
    @Test
    public void testSetGetId() {
        NvdCveInfo instance = new NvdCveInfo();
        String expResult = "id";
        instance.setId(expResult);
        String result = instance.getId();
        assertEquals(expResult, result);
    }

    /**
     * Test of getUrl method, of class NvdCveInfo.
     */
    @Test
    public void testSetGetUrl() {
        NvdCveInfo instance = new NvdCveInfo();
        String expResult = "http://www.someurl.com/something";
        instance.setUrl(expResult);
        String result = instance.getUrl();
        assertEquals(expResult, result);
    }

    /**
     * Test of getOldSchemaVersionUrl method, of class NvdCveInfo.
     */
    @Test
    public void testSetGetOldSchemaVersionUrl() {
        NvdCveInfo instance = new NvdCveInfo();
        String expResult = "http://www.someurl.com/something";
        instance.setOldSchemaVersionUrl(expResult);
        String result = instance.getOldSchemaVersionUrl();
        assertEquals(expResult, result);
    }

    /**
     * Test of getTimestamp method, of class NvdCveInfo.
     */
    @Test
    public void testSetGetTimestamp() {
        NvdCveInfo instance = new NvdCveInfo();
        long expResult = 1337L;
        instance.setTimestamp(expResult);
        long result = instance.getTimestamp();
        assertEquals(expResult, result);
    }

    /**
     * Test of getNeedsUpdate method, of class NvdCveInfo.
     */
    @Test
    public void testSetGetNeedsUpdate() {
        NvdCveInfo instance = new NvdCveInfo();
        boolean expResult = true;
        instance.setNeedsUpdate(expResult);
        boolean result = instance.getNeedsUpdate();
        assertEquals(expResult, result);
    }
}
