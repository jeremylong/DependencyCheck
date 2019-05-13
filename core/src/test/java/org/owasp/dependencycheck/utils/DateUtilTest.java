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
import org.owasp.dependencycheck.exception.ParseException;

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

        long current = c.getTimeInMillis() / 1000;
        long lastRun = current - (3 * (60 * 60 * 24));
        int range = 7; // 7 days
        boolean expResult = true;
        boolean result = DateUtil.withinDateRange(lastRun, current, range);
        assertEquals(expResult, result);

        lastRun = c.getTimeInMillis() / 1000 - (8 * (60 * 60 * 24));
        expResult = false;
        result = DateUtil.withinDateRange(lastRun, current, range);
        assertEquals(expResult, result);
    }

    /**
     * Test of parseXmlDate method, of class DateUtil.
     *
     * @throws ParseException thrown when there is a parse error
     */
    @Test
    public void testParseXmlDate() throws ParseException {
        String xsDate = "2019-01-02Z";
        Calendar result = DateUtil.parseXmlDate(xsDate);
        assertEquals(2019, result.get(Calendar.YEAR));
        //month is zero based.
        assertEquals(0, result.get(Calendar.MONTH));
        assertEquals(2, result.get(Calendar.DATE));
    }

    @Test
    public void testGetEpochValueInSeconds() throws ParseException {
        String milliseconds = "1550538553466";
        long expected = 1550538553;
        long result = DateUtil.getEpochValueInSeconds(milliseconds);
        assertEquals(expected, result);

        milliseconds = "blahblahblah";
        expected = 0;
        result = DateUtil.getEpochValueInSeconds(milliseconds);
        assertEquals(expected, result);

        milliseconds = "1550538553";
        expected = 1550538553;
        result = DateUtil.getEpochValueInSeconds(milliseconds);
        assertEquals(expected, result);
    }

}
