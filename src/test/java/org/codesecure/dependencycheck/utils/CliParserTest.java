/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import junit.framework.TestCase;
import org.apache.commons.cli.ParseException;
import org.junit.Test;

/**
 *
 * @author jeremy
 */
public class CliParserTest extends TestCase {

    public CliParserTest(String testName) {
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
     * Test of parse method, of class CliParser.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testParse() throws Exception {
        System.out.println("parse");

        String[] args = {};
        PrintStream out = System.out;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        CliParser instance = new CliParser();
        instance.parse(args);

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with help arg, of class CliParser.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testParse_help() throws Exception {
        System.out.println("parse -help");

        String[] args = {"-help"};
        PrintStream out = System.out;

        CliParser instance = new CliParser();
        instance.parse(args);

        assertFalse(instance.isGetVersion());
        assertTrue(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with version arg, of class CliParser.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testParse_version() throws Exception {
        System.out.println("parse -ver");

        String[] args = {"-version"};

        CliParser instance = new CliParser();
        instance.parse(args);
        assertTrue(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());

    }

    /**
     * Test of parse method with jar and cpe args, of class CliParser.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testParse_unknown() throws Exception {
        System.out.println("parse -unknown");

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
            assertTrue(ex.getMessage().contains("Unrecognized option"));
        }
        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with scan arg, of class CliParser.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testParse_scan() throws Exception {
        System.out.println("parse -scan");

        String[] args = {"-scan"};

        CliParser instance = new CliParser();

        try {
            instance.parse(args);
        } catch (ParseException ex) {
            assertTrue(ex.getMessage().contains("Missing argument"));
        }

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with jar arg, of class CliParser.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testParse_scan_unknownFile() throws Exception {
        System.out.println("parse -scan jar.that.does.not.exist");

        String[] args = {"-scan", "jar.that.does.not.exist", "-app", "test"};

        CliParser instance = new CliParser();
        try {
            instance.parse(args);
        } catch (FileNotFoundException ex) {
            assertTrue(ex.getMessage().contains("Invalid file argument"));
        }

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertFalse(instance.isRunScan());
    }

    /**
     * Test of parse method with jar arg, of class CliParser.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testParse_scan_withFileExists() throws Exception {
        System.out.println("parse -scan checkSumTest.file");
        File path = new File(this.getClass().getClassLoader().getResource("checkSumTest.file").getPath());
        String[] args = {"-scan", path.getCanonicalPath(), "-out", "./", "-app", "test"};

        CliParser instance = new CliParser();
        instance.parse(args);

        assertEquals(path.getCanonicalPath(), instance.getScanFiles()[0]);

        assertFalse(instance.isGetVersion());
        assertFalse(instance.isGetHelp());
        assertTrue(instance.isRunScan());
    }

    /**
     * Test of printVersionInfo, of class CliParser.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testParse_printVersionInfo() throws Exception {
        System.out.println("printVersionInfo");

        PrintStream out = System.out;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        CliParser instance = new CliParser();
        instance.printVersionInfo();
        try {
            baos.flush();
            String text = (new String(baos.toByteArray())).toLowerCase();
            String[] lines = text.split(System.getProperty("line.separator"));
            assertEquals(1, lines.length);
            assertTrue(text.contains("version"));
            assertTrue(!text.contains("unknown"));
        } catch (IOException ex) {
            System.setOut(out);
            fail("CliParser.printVersionInfo did not write anything to system.out.");
        } finally {
            System.setOut(out);
        }
    }

    /**
     * Test of printHelp, of class CliParser.
     * @throws Exception thrown when an excpetion occurs.
     */
    @Test
    public void testParse_printHelp() throws Exception {
        System.out.println("printHelp");

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
            assertTrue(lines[0].startsWith("usage: "));
            assertTrue((lines.length > 2));
        } catch (IOException ex) {
            System.setOut(out);
            fail("CliParser.printVersionInfo did not write anything to system.out.");
        } finally {
            System.setOut(out);
        }
    }
}
