/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.scanner;

import java.util.List;
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
public class DependencyTest {
    
    public DependencyTest() {
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
     * Test of containsUsedString method, of class Dependency.
     */
    @Test
    public void testContainsUsedString() {
        System.out.println("containsUsedString");
        String str = "apache";
        String str2 = "codesecure";
        Dependency instance = new Dependency();
        instance.vendorEvidence.addEvidence("manifest", "something", "apache", Evidence.Confidence.HIGH);
        instance.vendorEvidence.addEvidence("manifest", "something", "codesecure", Evidence.Confidence.MEDIUM);
        assertFalse(instance.containsUsedString(str));
        assertFalse(instance.containsUsedString(str2));
        for (Evidence i : instance.vendorEvidence.iterator(Evidence.Confidence.HIGH)) {
            String readValue = i.getValue();
        }
        assertTrue(instance.containsUsedString(str));
        assertFalse(instance.containsUsedString(str2));
        for (Evidence i : instance.vendorEvidence.iterator(Evidence.Confidence.MEDIUM)) {
            String readValue = i.getValue();
        }
        assertTrue(instance.containsUsedString(str));
        assertTrue(instance.containsUsedString(str2));
    }
}
