/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.utils;

import java.util.List;
import java.util.ArrayList;
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
public class FilterTest {

    public FilterTest() {
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
     * Test of passes method, of class Filter.
     */
    @Test
    public void testPasses() {
        System.out.println("passes");
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
        System.out.println("filter");
        List<String> testData = new ArrayList<String>();
        testData.add("keep");
        testData.add("remove");
        testData.add("keep");

        List<String> expResults = new ArrayList<String>();
        expResults.add("keep");
        expResults.add("keep");

        List<String> actResults = new ArrayList<String>();
        for (String s : TEST_FILTER.filter(testData)) {
            actResults.add(s);
        }
        assertArrayEquals(expResults.toArray(), actResults.toArray());
    }
    private static final Filter<String> TEST_FILTER =
            new Filter<String>() {

                public boolean passes(String str) {
                    return str.contains("keep");
                }
            };
}
