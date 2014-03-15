/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.taskdefs;

import java.io.File;
import static junit.framework.TestCase.assertTrue;
import org.apache.tools.ant.BuildFileTest;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
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
        File report = new File("target/dependency-check-report.html");
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
        File report = new File("target/dependency-check-report.xml");
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
        File report = new File("target/dependency-check-vulnerability.html");
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
