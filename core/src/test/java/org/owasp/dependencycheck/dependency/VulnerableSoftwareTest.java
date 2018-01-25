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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long
 */
public class VulnerableSoftwareTest extends BaseTest {

    /**
     * Test of equals method, of class VulnerableSoftware.
     */
    @Test
    public void testEquals() {
        VulnerableSoftware obj = new VulnerableSoftware();
        obj.setCpe("cpe:/a:mortbay:jetty:6.1.0");
        VulnerableSoftware instance = new VulnerableSoftware();
        instance.setCpe("cpe:/a:mortbay:jetty:6.1");
        assertFalse(instance.equals(obj));
    }

    /**
     * Test of equals method, of class VulnerableSoftware.
     */
    @Test
    public void testEquals2() {
        VulnerableSoftware obj = new VulnerableSoftware();
        obj.setCpe("cpe:/a:mortbay:jetty:6.1.0");
        VulnerableSoftware instance = new VulnerableSoftware();
        instance.setCpe("cpe:/a:mortbay:jetty:6.1.0");
        obj.setPreviousVersion("1");
        assertTrue(instance.equals(obj));
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
    public void testCompareToNonNumerical() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe("cpe:/a:mysql:mysql:5.1.23a");
        VulnerableSoftware vs1 = new VulnerableSoftware();
        vs1.setCpe("cpe:/a:mysql:mysql:5.1.23a");
        vs1.setPreviousVersion("1");
        assertEquals(0, vs.compareTo(vs1));
        assertEquals(0, vs1.compareTo(vs));
    }

    @Test
    public void testCompareToComplex() {
        VulnerableSoftware vs = new VulnerableSoftware();
        VulnerableSoftware vs1 = new VulnerableSoftware();

        vs.setCpe("2.1");
        vs1.setCpe("2.1.10");
        assertTrue(vs.compareTo(vs1) < 0);

        vs.setCpe("2.1.42");
        vs1.setCpe("2.3.21");
        assertTrue(vs.compareTo(vs1) < 0);

        vs.setCpe("cpe:/a:hp:system_management_homepage:2.1.1");
        vs1.setCpe("cpe:/a:hp:system_management_homepage:2.1.10");
        assertTrue(vs.compareTo(vs1) < 0);

        vs.setCpe("10");
        vs1.setCpe("10-186");
        assertTrue(vs.compareTo(vs1) < 0);

        vs.setCpe("2.1.10");
        vs1.setCpe("2.1.10-186");
        assertTrue(vs.compareTo(vs1) < 0);
        
        vs.setCpe("cpe:/a:hp:system_management_homepage:2.1.10");
        vs1.setCpe("cpe:/a:hp:system_management_homepage:2.1.10-186");
        assertTrue(vs.compareTo(vs1) < 0);
        //assertTrue(vs1.compareTo(vs)>0);

        vs.setCpe("cpe:/a:ibm:security_guardium_database_activity_monitor:10.01");
        vs1.setCpe("cpe:/a:ibm:security_guardium_database_activity_monitor:10.1");
        assertTrue(vs.compareTo(vs1) < 0);

        vs.setCpe("2.0");
        vs1.setCpe("2.1");
        assertTrue(vs.compareTo(vs1) < 0);
    }

    @Test
    public void testEqualsPreviousVersion() {
        VulnerableSoftware vs = new VulnerableSoftware();
        vs.setCpe("cpe:/a:mysql:mysql:5.1.23a");
        VulnerableSoftware vs1 = new VulnerableSoftware();
        vs1.setCpe("cpe:/a:mysql:mysql:5.1.23a");
        vs1.setPreviousVersion("1");
        assertEquals(vs, vs1);
        assertEquals(vs1, vs);

    }

    @Test
    public void testParseCPE() {
        VulnerableSoftware vs = new VulnerableSoftware();
        /* Version for test taken from CVE-2008-2079 */
        vs.setCpe("cpe:/a:mysql:mysql:5.1.23a");
        assertEquals("mysql", vs.getVendor());
        assertEquals("mysql", vs.getProduct());
        assertEquals("5.1.23a", vs.getVersion());
    }

    @Test
    public void testIspositiveInteger() {
        assertTrue(VulnerableSoftware.isPositiveInteger("1"));
        assertTrue(VulnerableSoftware.isPositiveInteger("10"));
        assertTrue(VulnerableSoftware.isPositiveInteger("666"));
        assertTrue(VulnerableSoftware.isPositiveInteger("0"));

        assertFalse(VulnerableSoftware.isPositiveInteger("+1"));
        assertFalse(VulnerableSoftware.isPositiveInteger("-1"));
        assertFalse(VulnerableSoftware.isPositiveInteger("2.1"));
        assertFalse(VulnerableSoftware.isPositiveInteger("01"));
        assertFalse(VulnerableSoftware.isPositiveInteger("00"));
    }
    
    @Test
    public void testVersionsWithLettersComparison() {
        VulnerableSoftware a = new VulnerableSoftware();
        a.setName("cpe:/a:mysql:mysql:5.0.3a");

        VulnerableSoftware b = new VulnerableSoftware();
        b.setName("cpe:/a:mysql:mysql:5.0.9");

        VulnerableSoftware c = new VulnerableSoftware();
        c.setName("cpe:/a:mysql:mysql:5.0.30");

        assertTrue(a.compareTo(b) < 0);
        assertTrue(a.compareTo(c) < 0);

        assertTrue(b.compareTo(a) > 0);
        assertTrue(b.compareTo(c) < 0);

        assertTrue(c.compareTo(a) > 0);
        assertTrue(c.compareTo(b) > 0);
    }
}
