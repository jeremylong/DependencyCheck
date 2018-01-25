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

import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long
 */
public class FilterTest extends BaseTest {

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
        List<String> testData = new ArrayList<>();
        testData.add("keep");
        testData.add("remove");
        testData.add("keep");

        List<String> expResults = new ArrayList<>();
        expResults.add("keep");
        expResults.add("keep");

        List<String> actResults = new ArrayList<String>();
        for (String s : TEST_FILTER.filter(testData)) {
            actResults.add(s);
        }
        assertArrayEquals(expResults.toArray(), actResults.toArray());
    }
    private static final Filter<String> TEST_FILTER
            = new Filter<String>() {
                @Override
                public boolean passes(String str) {
                    return str.contains("keep");
                }
            };
}
