/*
 * Copyright 2014 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.utils;

import java.util.Calendar;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long
 */
public class DateUtilTest extends BaseTest {

    /**
     * Test of withinDateRange method, of class DateUtil.
     */
    @Test
    public void testWithinDateRange() {
        Calendar c = Calendar.getInstance();

        long current = c.getTimeInMillis();
        long lastRun = c.getTimeInMillis() - (3 * (1000 * 60 * 60 * 24));
        int range = 7; // 7 days
        boolean expResult = true;
        boolean result = DateUtil.withinDateRange(lastRun, current, range);
        assertEquals(expResult, result);

        lastRun = c.getTimeInMillis() - (8 * (1000 * 60 * 60 * 24));
        expResult = false;
        result = DateUtil.withinDateRange(lastRun, current, range);
        assertEquals(expResult, result);
    }

}
