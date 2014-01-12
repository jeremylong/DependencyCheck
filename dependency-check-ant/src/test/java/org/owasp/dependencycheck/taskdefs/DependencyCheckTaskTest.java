/*
 * This file is part of dependency-check-ant.
 *
 * Dependency-check-ant is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-ant is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-ant. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.taskdefs;

import java.io.File;
import static junit.framework.TestCase.assertTrue;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.apache.tools.ant.BuildFileTest;
import org.owasp.dependencycheck.data.nvdcve.BaseDBTestCase;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DependencyCheckTaskTest extends BuildFileTest {

    public DependencyCheckTaskTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    @Override
    public void setUp() throws Exception {
        BaseDBTestCase.ensureDBExists();
        final String buildFile = this.getClass().getClassLoader().getResource("build.xml").getPath();
        configureProject(buildFile);
    }

    @After
    @Override
    public void tearDown() {
        //no cleanup...
        //executeTarget("cleanup");
    }

    /**
     * Test of addFileSet method, of class DependencyCheckTask.
     */
    @Test
    public void testAddFileSet() throws Exception {
        File report = new File("target/DependencyCheck-Report.html");
        if (report.exists()) {
            if (!report.delete()) {
                throw new Exception("Unable to delete 'target/DependencyCheck-Report.html' prior to test.");
            }
        }
        executeTarget("test.fileset");

        assertTrue("DependencyCheck report was not generated", report.exists());

    }

    /**
     * Test of addFileList method, of class DependencyCheckTask.
     *
     * @throws Exception
     */
    @Test
    public void testAddFileList() throws Exception {
        File report = new File("target/DependencyCheck-Report.xml");
        if (report.exists()) {
            if (!report.delete()) {
                throw new Exception("Unable to delete 'target/DependencyCheck-Report.xml' prior to test.");
            }
        }
        executeTarget("test.filelist");

        assertTrue("DependencyCheck report was not generated", report.exists());
    }

    /**
     * Test of addDirSet method, of class DependencyCheckTask.
     *
     * @throws Exception
     */
    @Test
    public void testAddDirSet() throws Exception {
        File report = new File("target/DependencyCheck-Vulnerability.html");
        if (report.exists()) {
            if (!report.delete()) {
                throw new Exception("Unable to delete 'target/DependencyCheck-Vulnerability.html' prior to test.");
            }
        }
        executeTarget("test.dirset");
        assertTrue("DependencyCheck report was not generated", report.exists());
    }

    /**
     * Test of getFailBuildOnCVSS method, of class DependencyCheckTask.
     */
    @Test
    public void testGetFailBuildOnCVSS() {
        expectBuildException("failCVSS", "asdfasdfscore");
        System.out.println(this.getOutput());
    }
}
