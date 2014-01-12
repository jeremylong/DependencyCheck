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
package org.owasp.dependencycheck.suppression;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class PropertyTypeTest {

    public PropertyTypeTest() {
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
     * Test of set and getValue method, of class PropertyType.
     */
    @Test
    public void testSetGetValue() {

        PropertyType instance = new PropertyType();
        String expResult = "test";
        instance.setValue(expResult);
        String result = instance.getValue();
        assertEquals(expResult, result);
    }

    /**
     * Test of isRegex method, of class PropertyType.
     */
    @Test
    public void testIsRegex() {
        PropertyType instance = new PropertyType();
        boolean result = instance.isRegex();
        assertFalse(instance.isRegex());
        instance.setRegex(true);
        assertTrue(instance.isRegex());
    }

    /**
     * Test of isCaseSensitive method, of class PropertyType.
     */
    @Test
    public void testIsCaseSensitive() {
        PropertyType instance = new PropertyType();
        assertFalse(instance.isCaseSensitive());
        instance.setCaseSensitive(true);
        assertTrue(instance.isCaseSensitive());
    }

    /**
     * Test of matches method, of class PropertyType.
     */
    @Test
    public void testMatches() {
        String text = "Simple";

        PropertyType instance = new PropertyType();
        instance.setValue("simple");
        assertTrue(instance.matches(text));
        instance.setCaseSensitive(true);
        assertFalse(instance.matches(text));

        instance.setValue("s.*le");
        instance.setRegex(true);
        assertFalse(instance.matches(text));
        instance.setCaseSensitive(false);
        assertTrue(instance.matches(text));
    }
}
