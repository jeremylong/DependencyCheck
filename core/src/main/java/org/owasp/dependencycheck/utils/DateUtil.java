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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.owasp.dependencycheck.exception.ParseException;

import java.util.Calendar;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class DateUtil {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DateUtil.class);

    /**
     * Private constructor for utility class.
     */
    private DateUtil() {
    }

    /**
     * Parses an XML xs:date into a calendar object.
     *
     * @param xsDate an xs:date string
     * @return a calendar object
     * @throws ParseException thrown if the date cannot be converted to a
     * calendar
     */
    public static Calendar parseXmlDate(String xsDate) throws ParseException {
        try {
            final DatatypeFactory df = DatatypeFactory.newInstance();
            final XMLGregorianCalendar dateTime = df.newXMLGregorianCalendar(xsDate);
            return dateTime.toGregorianCalendar();
        } catch (DatatypeConfigurationException ex) {
            throw new ParseException("Unable to parse " + xsDate, ex);
        }
    }

    /**
     * Determines if the epoch date is within the range specified of the
     * compareTo epoch time. This takes the (compareTo-date)/1000/60/60/24 to
     * get the number of days. If the calculated days is less then the range the
     * date is considered valid.
     *
     * @param date the date to be checked.
     * @param compareTo the date to compare to.
     * @param dayRange the range in days to be considered valid.
     * @return whether or not the date is within the range.
     */
    public static boolean withinDateRange(long date, long compareTo, int dayRange) {
        // ms = dayRange x 24 hours/day x 60 min/hour x 60 sec/min x 1000 ms/sec
        final long msRange = dayRange * 24L * 60L * 60L;
        return (compareTo - date) < msRange;
    }

    /**
     * Returns the string value converted to an epoch seconds. Note, in some
     * cases the value provided may be in milliseconds.
     *
     * @param epoch the property value
     * @return the value in seconds
     */
    public static long getEpochValueInSeconds(String epoch) {
        final String seconds;
        if (epoch.length() >= 13) {
            //this is in milliseconds - reduce to seconds
            seconds = epoch.substring(0, 10);
        } else {
            seconds = epoch;
        }
        long results = 0;
        try {
            results = Long.parseLong(seconds);
        } catch (NumberFormatException ex) {
            LOGGER.debug(String.format("Error parsing '%s' property from the database - using zero", epoch), ex);
        }
        return results;
    }
}
