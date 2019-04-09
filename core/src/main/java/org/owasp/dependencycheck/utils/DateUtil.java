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

/**
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class DateUtil {

    /**
     * Private constructor for utility class.
     */
    private DateUtil() {
    }

    /**
     * Parses an XML xs:date into a calendar object.
     * @param xsDate an xs:date string
     * @return a calendar object
     * @throws ParseException thrown if the date cannot be converted to a calendar
     */
    public static Calendar parseXmlDate(String xsDate) throws ParseException {
        try {
            DatatypeFactory df = DatatypeFactory.newInstance();
            XMLGregorianCalendar dateTime = df.newXMLGregorianCalendar(xsDate);
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
        final long msRange = dayRange * 24L * 60L * 60L * 1000L;
        return (compareTo - date) < msRange;
    }
}
