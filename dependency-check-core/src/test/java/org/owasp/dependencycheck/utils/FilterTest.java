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

import org.owasp.dependencycheck.utils.Filter;
import java.util.List;
import java.util.ArrayList;
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
public class FilterTest {

    public FilterTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of passes method, of class Filter.
     */
    @Test
    public void testPasses() {
        String keep = "keep";
        String fail = "fail";

        assertTrue("String contained keep - but passes returned false.", TEST_FILTER.passes(keep));
        assertFalse("String contained fail - but passes returned true.", TEST_FILTER.passes(fail));
    }

    /**
     * Test of filter method, of class Filter.
     */
    @Test
    public void testFilter_Iterable() {
        List<String> testData = new ArrayList<String>();
        testData.add("keep");
        testData.add("remove");
        testData.add("keep");

        List<String> expResults = new ArrayList<String>();
        expResults.add("keep");
        expResults.add("keep");

        List<String> actResults = new ArrayList<String>();
        for (String s : TEST_FILTER.filter(testData)) {
            actResults.add(s);
        }
        assertArrayEquals(expResults.toArray(), actResults.toArray());
    }
    private static final Filter<String> TEST_FILTER =
            new Filter<String>() {
        public boolean passes(String str) {
            return str.contains("keep");
        }
    };
}
