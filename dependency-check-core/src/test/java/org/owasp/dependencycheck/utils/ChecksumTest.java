/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.owasp.dependencycheck.utils.Checksum;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class ChecksumTest {

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    /**
     * Test of getChecksum method, of class Checksum.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testGetChecksum() throws Exception {
        String algorithm = "MD5";
        File file = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").getPath());
        byte[] expResult = {-16, -111, 92, 95, 70, -72, -49, -94, -125, -27, -83, 103, -96, -101, 55, -109};
        byte[] result = Checksum.getChecksum(algorithm, file);
        boolean arraysAreEqual = true;
        if (expResult.length == result.length) {
            for (int i = 0; arraysAreEqual && i < result.length; i++) {
                arraysAreEqual = result[i] == expResult[i];
            }
        } else {
            Assert.fail("Checksum results do not match expected results.");
        }
        Assert.assertTrue(arraysAreEqual);
    }

    /**
     * Test of getChecksum method, of class Checksum. This checks that an
     * exception is thrown when an invalid path is specified.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGetChecksum_FileNotFound() throws Exception {
        String algorithm = "MD5";
        File file = new File("not a valid file");
        boolean exceptionThrown = false;
        try {
            byte[] result = Checksum.getChecksum(algorithm, file);
        } catch (IOException ex) {
            exceptionThrown = true;
        }
        Assert.assertTrue(exceptionThrown);
    }

    /**
     * Test of getChecksum method, of class Checksum. This checks that an
     * exception is thrown when an invalid algorithm is specified.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGetChecksum_NoSuchAlgorithm() throws Exception {
        String algorithm = "some unknown algorithm";
        File file = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").getPath());
        boolean exceptionThrown = false;
        try {
            byte[] result = Checksum.getChecksum(algorithm, file);
        } catch (NoSuchAlgorithmException ex) {
            exceptionThrown = true;
        }
        Assert.assertTrue(exceptionThrown);
    }

    /**
     * Test of getMD5Checksum method, of class Checksum.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGetMD5Checksum() throws Exception {
        File file = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").getPath());
        String expResult = "F0915C5F46B8CFA283E5AD67A09B3793";
        String result = Checksum.getMD5Checksum(file);
        Assert.assertEquals(expResult, result);
    }

    /**
     * Test of getSHA1Checksum method, of class Checksum.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGetSHA1Checksum() throws Exception {
        File file = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").getPath());
        String expResult = "B8A9FF28B21BCB1D0B50E24A5243D8B51766851A";
        String result = Checksum.getSHA1Checksum(file);
        Assert.assertEquals(expResult, result);
    }

    /**
     * Test of getHex method, of class Checksum.
     */
    @Test
    public void testGetHex() {
        byte[] raw = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        String expResult = "000102030405060708090A0B0C0D0E0F10";
        String result = Checksum.getHex(raw);
        Assert.assertEquals(expResult, result);
    }
}
