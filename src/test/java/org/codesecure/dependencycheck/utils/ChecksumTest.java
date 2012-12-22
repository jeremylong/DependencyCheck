/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.utils;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import junit.framework.TestCase;
import org.junit.Test;

/**
 *
 * @author jeremy
 */
public class ChecksumTest extends TestCase {

    public ChecksumTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of getChecksum method, of class Checksum.
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testGetChecksum() throws Exception {
        System.out.println("getChecksum (md5)");
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
            fail("Checksum results do not match expected results.");
        }
        assertTrue(arraysAreEqual);
    }

    /**
     * Test of getChecksum method, of class Checksum. This checks that an
     * excpetion is thrown when an invalid path is specified.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGetChecksum_FileNotFound() throws Exception {
        System.out.println("getChecksum (invalid path)");
        String algorithm = "MD5";
        File file = new File("not a valid file");
        boolean exceptionThrown = false;
        try {
            byte[] result = Checksum.getChecksum(algorithm, file);
        } catch (IOException ex) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);
    }

    /**
     * Test of getChecksum method, of class Checksum. This checks that an
     * exception is thrown when an invalid algorithm is specified.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGetChecksum_NoSuchAlgorithm() throws Exception {
        System.out.println("getChecksum (invalid algorithm)");
        String algorithm = "some unknown algorithm";
        File file = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").getPath());
        boolean exceptionThrown = false;
        try {
            byte[] result = Checksum.getChecksum(algorithm, file);
        } catch (NoSuchAlgorithmException ex) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);
    }

    /**
     * Test of getMD5Checksum method, of class Checksum.
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGetMD5Checksum() throws Exception {
        System.out.println("getMD5Checksum");
        File file = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").getPath());
        String expResult = "F0915C5F46B8CFA283E5AD67A09B3793";
        String result = Checksum.getMD5Checksum(file);
        assertEquals(expResult, result);
    }

    /**
     * Test of getSHA1Checksum method, of class Checksum.
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGetSHA1Checksum() throws Exception {
        System.out.println("getSHA1Checksum");
        File file = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").getPath());
        String expResult = "B8A9FF28B21BCB1D0B50E24A5243D8B51766851A";
        String result = Checksum.getSHA1Checksum(file);
        assertEquals(expResult, result);
    }

    /**
     * Test of getHex method, of class Checksum.
     */
    @Test
    public void testGetHex() {
        System.out.println("getHex");
        byte[] raw = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        String expResult = "000102030405060708090A0B0C0D0E0F10";
        String result = Checksum.getHex(raw);
        assertEquals(expResult, result);
    }
}
