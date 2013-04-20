/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.dependency;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class VulnerableSoftwareTest {

    public VulnerableSoftwareTest() {
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
    }
}
