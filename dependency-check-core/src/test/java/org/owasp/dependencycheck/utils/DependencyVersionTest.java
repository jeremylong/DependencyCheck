/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.utils;

import java.util.Iterator;
import java.util.List;
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
public class DependencyVersionTest {

    public DependencyVersionTest() {
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
     * Test of parseVersion method, of class DependencyVersion.
     */
    @Test
    public void testParseVersion() {
        String version = "1.2r1";
        DependencyVersion instance = new DependencyVersion();
        instance.parseVersion(version);
        List<String> parts = instance.getVersionParts();
        assertEquals(3, parts.size());
        assertEquals("1", parts.get(0));
        assertEquals("2", parts.get(1));
        assertEquals("r1", parts.get(2));

        instance.parseVersion("x6.0");
        parts = instance.getVersionParts();
        assertEquals(2, parts.size());
        assertEquals("x6", parts.get(0));
        assertEquals("0", parts.get(1));
        //assertEquals("0", parts.get(2));


    }

    /**
     * Test of iterator method, of class DependencyVersion.
     */
    @Test
    public void testIterator() {
        DependencyVersion instance = new DependencyVersion("1.2.3");
        Iterator result = instance.iterator();
        int count = 1;
        while (result.hasNext()) {
            String v = (String) result.next();
            assertTrue(String.valueOf(count++).equals(v));
        }
    }

    /**
     * Test of toString method, of class DependencyVersion.
     */
    @Test
    public void testToString() {
        DependencyVersion instance = new DependencyVersion("1.2.3r1");
        String expResult = "1.2.3.r1";
        String result = instance.toString();
        assertEquals(expResult, result);
    }

    /**
     * Test of equals method, of class DependencyVersion.
     */
    @Test
    public void testEquals() {
        DependencyVersion obj = new DependencyVersion("1.2.3.r1");
        DependencyVersion instance = new DependencyVersion("1.2.3");
        boolean expResult = false;
        boolean result = instance.equals(obj);
        assertEquals(expResult, result);
        obj = new DependencyVersion("1.2.3");
        expResult = true;
        result = instance.equals(obj);
        assertEquals(expResult, result);
    }

    /**
     * Test of hashCode method, of class DependencyVersion.
     */
    @Test
    public void testHashCode() {
        DependencyVersion instance = new DependencyVersion("3.2.1");
        int expResult = 80756;
        int result = instance.hashCode();
        assertEquals(expResult, result);
    }

    /**
     * Test of matchesAtLeastThreeLevels method, of class DependencyVersion.
     */
    @Test
    public void testMatchesAtLeastThreeLevels() {

        DependencyVersion instance = new DependencyVersion("1.2.3.4");
        DependencyVersion version = new DependencyVersion("1.2.3.5");
        //true tests
        assertEquals(true, instance.matchesAtLeastThreeLevels(version));
        version = new DependencyVersion("1.2");
        assertEquals(true, instance.matchesAtLeastThreeLevels(version));
        //false tests
        version = new DependencyVersion("1.2.2.5");
        assertEquals(false, instance.matchesAtLeastThreeLevels(version));
        version = new DependencyVersion("2");
        assertEquals(false, instance.matchesAtLeastThreeLevels(version));
    }

    /**
     * Test of compareTo method, of class DependencyVersion.
     */
    @Test
    public void testCompareTo() {
        DependencyVersion instance = new DependencyVersion("1.2.3");
        DependencyVersion version = new DependencyVersion("1.2.3");
        int expResult = 0;
        assertEquals(0, instance.compareTo(version));
        version = new DependencyVersion("1.1");
        assertEquals(1, instance.compareTo(version));
        version = new DependencyVersion("1.2");
        assertEquals(1, instance.compareTo(version));
        version = new DependencyVersion("1.3");
        assertEquals(-1, instance.compareTo(version));
        version = new DependencyVersion("1.2.3.1");
        assertEquals(-1, instance.compareTo(version));

        DependencyVersion[] dv = new DependencyVersion[7];
        dv[0] = new DependencyVersion("2.1.3");
        dv[1] = new DependencyVersion("2.1.3.r2");
        dv[2] = new DependencyVersion("2.1.3.r1");
        dv[3] = new DependencyVersion("1.2.3.1");
        dv[4] = new DependencyVersion("1.2.3");
        dv[5] = new DependencyVersion("2");
        dv[6] = new DependencyVersion("-");

        DependencyVersion[] expected = new DependencyVersion[7];
        expected[0] = new DependencyVersion("-");
        expected[1] = new DependencyVersion("1.2.3");
        expected[2] = new DependencyVersion("1.2.3.1");
        expected[3] = new DependencyVersion("2");
        expected[4] = new DependencyVersion("2.1.3");
        expected[5] = new DependencyVersion("2.1.3.r1");
        expected[6] = new DependencyVersion("2.1.3.r2");
        java.util.Arrays.sort(dv);

        assertArrayEquals(expected, dv);
    }
}
