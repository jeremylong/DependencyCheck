/*
 * This file is part of dependency-check-maven.
 *
 * Dependency-check-maven is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-maven is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-maven. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import org.apache.maven.plugin.testing.AbstractMojoTestCase;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.File;
import java.util.Locale;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * TODO - figure out how to get the test harness to work. ATM no tests are
 * running.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DependencyCheckMojoTest extends AbstractMojoTestCase {

    public DependencyCheckMojoTest() {
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
//
//    /**
//     * Test of execute method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testExecute() throws Exception {
//        System.out.println("execute");
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        instance.execute();
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of generate method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testGenerate_Sink_Locale() throws Exception {
//        System.out.println("generate");
//        org.codehaus.doxia.sink.Sink sink = null;
//        Locale locale = null;
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        instance.generate(sink, locale);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }

    /**
     * Test of generate method, of class DependencyCheckMojo.
     */
    @Test
    public void testGenerate_Sink_SinkFactory_Locale() throws Exception {
        //can't get the test-harness to work.
//        File samplePom = new File(this.getClass().getClassLoader().getResource("sample.xml").toURI());
//        DependencyCheckMojo mojo = (DependencyCheckMojo) lookupMojo("check", samplePom);
//        assertNotNull("Unable to load mojo", mojo);
//
//        File out = mojo.getReportOutputDirectory();
//        OutputStream os = new FileOutputStream(out);
//        MySink sink = new MySink(os);
//        Locale locale = new Locale("en");
//
//
//        mojo.generate(sink, null, locale);
//        sink.close();
    }
//    /**
//     * Test of getOutputName method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testGetOutputName() {
//        System.out.println("getOutputName");
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        String expResult = "";
//        String result = instance.getOutputName();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getCategoryName method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testGetCategoryName() {
//        System.out.println("getCategoryName");
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        String expResult = "";
//        String result = instance.getCategoryName();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getName method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testGetName() {
//        System.out.println("getName");
//        Locale locale = null;
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        String expResult = "";
//        String result = instance.getName(locale);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setReportOutputDirectory method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testSetReportOutputDirectory() {
//        System.out.println("setReportOutputDirectory");
//        File directory = null;
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        instance.setReportOutputDirectory(directory);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getReportOutputDirectory method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testGetReportOutputDirectory() {
//        System.out.println("getReportOutputDirectory");
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        File expResult = null;
//        File result = instance.getReportOutputDirectory();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getDescription method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testGetDescription() {
//        System.out.println("getDescription");
//        Locale locale = null;
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        String expResult = "";
//        String result = instance.getDescription(locale);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of isExternalReport method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testIsExternalReport() {
//        System.out.println("isExternalReport");
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        boolean expResult = false;
//        boolean result = instance.isExternalReport();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of canGenerateReport method, of class DependencyCheckMojo.
//     */
//    @Test
//    public void testCanGenerateReport() {
//        System.out.println("canGenerateReport");
//        DependencyCheckMojo instance = new DependencyCheckMojo();
//        boolean expResult = false;
//        boolean result = instance.canGenerateReport();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
}
