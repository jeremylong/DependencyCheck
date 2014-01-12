/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.cli;

import org.owasp.dependencycheck.cli.CliParser;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import org.apache.commons.cli.ParseException;
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
public class CliParserTest {

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
     * Test of parse method, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse() throws Exception {

        String[] args = {};
        PrintStream out = System.out;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        CliParser instance = new CliParser();
        instance.parse(args);

        Assert.assertFalse(instance.isGetVersion());
        Assert.assertFalse(instance.isGetHelp());
        Assert.assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with help arg, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_help() throws Exception {

        String[] args = {"-help"};
        PrintStream out = System.out;

        CliParser instance = new CliParser();
        instance.parse(args);

        Assert.assertFalse(instance.isGetVersion());
        Assert.assertTrue(instance.isGetHelp());
        Assert.assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with version arg, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_version() throws Exception {

        String[] args = {"-version"};

        CliParser instance = new CliParser();
        instance.parse(args);
        Assert.assertTrue(instance.isGetVersion());
        Assert.assertFalse(instance.isGetHelp());
        Assert.assertFalse(instance.isRunScan());

    }

    /**
     * Test of parse method with jar and cpe args, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_unknown() throws Exception {

        String[] args = {"-unknown"};

        PrintStream out = System.out;
        PrintStream err = System.err;
        ByteArrayOutputStream baos_out = new ByteArrayOutputStream();
        ByteArrayOutputStream baos_err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos_out));
        System.setErr(new PrintStream(baos_err));

        CliParser instance = new CliParser();

        try {
            instance.parse(args);
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getMessage().contains("Unrecognized option"));
        }
        Assert.assertFalse(instance.isGetVersion());
        Assert.assertFalse(instance.isGetHelp());
        Assert.assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with scan arg, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_scan() throws Exception {

        String[] args = {"-scan"};

        CliParser instance = new CliParser();

        try {
            instance.parse(args);
        } catch (ParseException ex) {
            Assert.assertTrue(ex.getMessage().contains("Missing argument"));
        }

        Assert.assertFalse(instance.isGetVersion());
        Assert.assertFalse(instance.isGetHelp());
        Assert.assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with jar arg, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_scan_unknownFile() throws Exception {

        String[] args = {"-scan", "jar.that.does.not.exist", "-app", "test"};

        CliParser instance = new CliParser();
        try {
            instance.parse(args);
        } catch (FileNotFoundException ex) {
            Assert.assertTrue(ex.getMessage().contains("Invalid 'scan' argument"));
        }

        Assert.assertFalse(instance.isGetVersion());
        Assert.assertFalse(instance.isGetHelp());
        Assert.assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with jar arg, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_scan_withFileExists() throws Exception {
        File path = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").getPath());
        String[] args = {"-scan", path.getCanonicalPath(), "-out", "./", "-app", "test"};

        CliParser instance = new CliParser();
        instance.parse(args);

        Assert.assertEquals(path.getCanonicalPath(), instance.getScanFiles()[0]);

        Assert.assertFalse(instance.isGetVersion());
        Assert.assertFalse(instance.isGetHelp());
        Assert.assertTrue(instance.isRunScan());
    }

    /**
     * Test of printVersionInfo, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_printVersionInfo() throws Exception {

        PrintStream out = System.out;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        CliParser instance = new CliParser();
        instance.printVersionInfo();
        try {
            baos.flush();
            String text = (new String(baos.toByteArray())).toLowerCase();
            String[] lines = text.split(System.getProperty("line.separator"));
            Assert.assertEquals(1, lines.length);
            Assert.assertTrue(text.contains("version"));
            Assert.assertTrue(!text.contains("unknown"));
        } catch (IOException ex) {
            System.setOut(out);
            Assert.fail("CliParser.printVersionInfo did not write anything to system.out.");
        } finally {
            System.setOut(out);
        }
    }

    /**
     * Test of printHelp, of class CliParser.
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_printHelp() throws Exception {

        PrintStream out = System.out;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        CliParser instance = new CliParser();
        String[] args = {"-h"};
        instance.parse(args);
        instance.printHelp();
        args[0] = "-ah";
        instance.parse(args);
        instance.printHelp();
        try {
            baos.flush();
            String text = (new String(baos.toByteArray()));
            String[] lines = text.split(System.getProperty("line.separator"));
            Assert.assertTrue(lines[0].startsWith("usage: "));
            Assert.assertTrue((lines.length > 2));
        } catch (IOException ex) {
            System.setOut(out);
            Assert.fail("CliParser.printVersionInfo did not write anything to system.out.");
        } finally {
            System.setOut(out);
        }
    }
}
