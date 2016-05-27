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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.dependency;

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long
 */
public class VulnerableSoftwareTest extends BaseTest  {

    /**
     * Test of equals method, of class VulnerableSoftware.
     */
    @Test
    public void testEquals() {
        VulnerableSoftware obj = new VulnerableSoftware();
        obj.setCpe("cpe:/a:mortbay:jetty:6.1.0");
        VulnerableSoftware instance = new VulnerableSoftware();
        instance.setCpe("cpe:/a:mortbay:jetty:6.1");
        boolean expResult = false;
        boolean result = instance.equals(obj);
        assertEquals(expResult, result);
    }

    /**
     * Test of hashCode method, of class VulnerableSoftware.
     */
    @Test
    public void testHashCode() {
        VulnerableSoftware instance = new VulnerableSoftware();
        instance.setCpe("cpe:/a:mortbay:jetty:6.1");
        int expResult = 1849413912;
        int result = instance.hashCode();
        assertEquals(expResult, result);
    }

    /**
     * Test of compareTo method, of class VulnerableSoftware.
     */
    @Test
    public void testCompareTo() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe("cpe:/a:mortbay:jetty:6.1.0");
        VulnerableSoftware instance = new VulnerableSoftware();
        instance.setCpe("cpe:/a:mortbay:jetty:6.1");
        int expResult = -2;
        int result = instance.compareTo(vs);
        assertEquals(expResult, result);

        vs = new VulnerableSoftware();
        vs.setCpe("cpe:/a:yahoo:toolbar:3.1.0.20130813024103");
        instance = new VulnerableSoftware();
        instance.setCpe("cpe:/a:yahoo:toolbar:3.1.0.20130813024104");
        expResult = 1;
        result = instance.compareTo(vs);
        assertEquals(expResult, result);
    }

    @Test
    public void testParseCPE() {
        VulnerableSoftware vs = new VulnerableSoftware();
        /* Version for test taken from CVE-2008-2079 */
        vs.setCpe("cpe:/a:mysql:mysql:5.0.0:alpha");
        assertEquals("mysql", vs.getVendor());
        assertEquals("mysql", vs.getProduct());
        assertEquals("5.0.0:alpha", vs.getVersion());
    }
}
