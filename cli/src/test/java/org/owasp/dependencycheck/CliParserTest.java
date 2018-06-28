/*
 * This file is part of Dependency-Check.
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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import org.apache.commons.cli.ParseException;
import org.junit.Assert;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 *
 * @author Jeremy Long
 */
public class CliParserTest extends BaseTest {

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

        CliParser instance = new CliParser(getSettings());
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

        CliParser instance = new CliParser(getSettings());
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

        CliParser instance = new CliParser(getSettings());
        instance.parse(args);
        Assert.assertTrue(instance.isGetVersion());
        Assert.assertFalse(instance.isGetHelp());
        Assert.assertFalse(instance.isRunScan());

    }

    /**
     * Test of parse method with failOnCVSS without an argument
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_failOnCVSSNoArg() throws Exception {

        String[] args = {"--failOnCVSS"};

        CliParser instance = new CliParser(getSettings());
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
     * Test of parse method with failOnCVSS invalid argument. It should default
     * to 11
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_failOnCVSSInvalidArgument() throws Exception {

        String[] args = {"--failOnCVSS", "bad"};

        CliParser instance = new CliParser(getSettings());
        instance.parse(args);
        Assert.assertEquals("Default should be 11", 11, instance.getFailOnCVSS());
        Assert.assertFalse(instance.isGetVersion());
        Assert.assertFalse(instance.isGetHelp());
        Assert.assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with failOnCVSS invalid argument. It should default
     * to 11
     *
     * @throws Exception thrown when an exception occurs.
     */
    @Test
    public void testParse_failOnCVSSValidArgument() throws Exception {

        String[] args = {"--failOnCVSS", "6"};

        CliParser instance = new CliParser(getSettings());
        instance.parse(args);
        Assert.assertEquals(6, instance.getFailOnCVSS());
        Assert.assertFalse(instance.isGetVersion());
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

        CliParser instance = new CliParser(getSettings());

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

        CliParser instance = new CliParser(getSettings());

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

        CliParser instance = new CliParser(getSettings());
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
        File path = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").toURI().getPath());
        String[] args = {"-scan", path.getCanonicalPath(), "-out", "./", "-app", "test"};

        CliParser instance = new CliParser(getSettings());
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

        CliParser instance = new CliParser(getSettings());
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

        CliParser instance = new CliParser(getSettings());
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

    /**
     * Test of getBooleanArgument method, of class CliParser.
     */
    @Test
    public void testGetBooleanArgument() throws ParseException {
        String[] args = {"--scan", "missing.file", "--artifactoryUseProxy", "false", "--artifactoryParallelAnalysis", "true", "--project", "test"};

        CliParser instance = new CliParser(getSettings());
        try {
            instance.parse(args);
        } catch (FileNotFoundException ex) {
            Assert.assertTrue(ex.getMessage().contains("Invalid 'scan' argument"));
        }
        Boolean expResult = null;
        Boolean result = instance.getBooleanArgument("missingArgument");
        Assert.assertNull(result);

        expResult = false;
        result = instance.getBooleanArgument(CliParser.ARGUMENT.ARTIFACTORY_USES_PROXY);
        assertEquals(expResult, result);
        expResult = true;
        result = instance.getBooleanArgument(CliParser.ARGUMENT.ARTIFACTORY_PARALLEL_ANALYSIS);
        assertEquals(expResult, result);
    }

    /**
     * Test of getStringArgument method, of class CliParser.
     */
    @Test
    public void testGetStringArgument() throws ParseException {

        String[] args = {"--scan", "missing.file", "--artifactoryUsername", "blue42", "--project", "test"};

        CliParser instance = new CliParser(getSettings());
        try {
            instance.parse(args);
        } catch (FileNotFoundException ex) {
            Assert.assertTrue(ex.getMessage().contains("Invalid 'scan' argument"));
        }
        String expResult = null;
        String result = instance.getStringArgument("missingArgument");
        Assert.assertNull(result);

        expResult = "blue42";
        result = instance.getStringArgument(CliParser.ARGUMENT.ARTIFACTORY_USERNAME);
        assertEquals(expResult, result);
    }
    
        /**
     * Test of getStringArgument method, of class CliParser.
     */
    @Test
    public void testHasArgument() throws ParseException {

        String[] args = {"--scan", "missing.file", "--artifactoryUsername", "blue42", "--project", "test"};

        CliParser instance = new CliParser(getSettings());
        try {
            instance.parse(args);
        } catch (FileNotFoundException ex) {
            Assert.assertTrue(ex.getMessage().contains("Invalid 'scan' argument"));
        }
        boolean expResult = false;
        boolean result = instance.hasArgument("missingArgument");
        assertEquals(expResult, result);

        expResult = true;
        result = instance.hasArgument(CliParser.ARGUMENT.PROJECT);
        assertEquals(expResult, result);
    }
}
