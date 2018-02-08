/*
 * This file is part of dependency-check-core.
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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import java.io.File;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long
 */
public class DriverLoaderTest extends BaseTest {

    /**
     * Test of load method, of class DriverLoader.
     *
     * @throws java.sql.SQLException thrown if there is an error de-registering
     * the driver
     */
    @Test
    public void testLoad_String() throws SQLException {
        String className = "org.h2.Driver";
        Driver d = null;
        try {
            d = DriverLoader.load(className);
        } catch (DriverLoadException ex) {
            fail(ex.getMessage());
        } finally {
            if (d != null) {
                DriverManager.deregisterDriver(d);
            }
        }
    }

    /**
     * Test of load method, of class DriverLoader; expecting an exception due to
     * a bad driver class name.
     */
    @Test(expected = DriverLoadException.class)
    public void testLoad_String_ex() throws Exception {
        final String className = "bad.Driver";
        DriverLoader.load(className);
    }

    /**
     * Test of load method, of class DriverLoader.
     */
    @Test
    public void testLoad_String_String() throws Exception {
        String className = "com.mysql.jdbc.Driver";
        //we know this is in target/test-classes
        //File testClassPath = (new File(this.getClass().getClassLoader().getResource("org.mortbay.jetty.jar").getPath())).getParentFile();
        File testClassPath = BaseTest.getResourceAsFile(this, "org.mortbay.jetty.jar").getParentFile();
        File driver = new File(testClassPath, "../../src/test/resources/mysql-connector-java-5.1.27-bin.jar");
        assertTrue("MySQL Driver JAR file not found in src/test/resources?", driver.isFile());

        Driver d = null;
        try {
            d = DriverLoader.load(className, driver.getAbsolutePath());
            d = DriverManager.getDriver("jdbc:mysql://localhost:3306/dependencycheck");
            assertNotNull(d);
        } finally {
            if (d != null) {
                DriverManager.deregisterDriver(d);
            }
        }
    }

    /**
     * Test of load method, of class DriverLoader.
     */
    @Test
    public void testLoad_String_String_multiple_paths()  {
        final String className = "com.mysql.jdbc.Driver";
        //we know this is in target/test-classes
        //final File testClassPath = (new File(this.getClass().getClassLoader().getResource("org.mortbay.jetty.jar").getPath())).getParentFile();
        final File testClassPath = BaseTest.getResourceAsFile(this, "org.mortbay.jetty.jar").getParentFile();
        final File dir1 = new File(testClassPath, "../../src/test/");
        final File dir2 = new File(testClassPath, "../../src/test/resources/");
        final String paths = String.format("%s" + File.pathSeparator + "%s", dir1.getAbsolutePath(), dir2.getAbsolutePath());

        Driver d = null;
        try {
            d = DriverLoader.load(className, paths);
        } catch (DriverLoadException ex) {
            fail(ex.getMessage());
        } finally {
            if (d != null) {
                try {
                    DriverManager.deregisterDriver(d);
                } catch (SQLException ex) {
                    fail(ex.getMessage());
                }
            }
        }
    }

    /**
     * Test of load method, of class DriverLoader with an incorrect class name.
     */
    @Test(expected = DriverLoadException.class)
    public void testLoad_String_String_badClassName() throws Exception {
        String className = "com.mybad.jdbc.Driver";
        //we know this is in target/test-classes
        //File testClassPath = (new File(this.getClass().getClassLoader().getResource("org.mortbay.jetty.jar").getPath())).getParentFile();
        File testClassPath = BaseTest.getResourceAsFile(this, "org.mortbay.jetty.jar").getParentFile();
        File driver = new File(testClassPath, "../../src/test/resources/mysql-connector-java-5.1.27-bin.jar");
        assertTrue("MySQL Driver JAR file not found in src/test/resources?", driver.isFile());

        DriverLoader.load(className, driver.getAbsolutePath());
    }

    /**
     * Test of load method, of class DriverLoader with an incorrect class path.
     */
    @Test(expected = DriverLoadException.class)
    public void testLoad_String_String_badPath() throws Exception {
        String className = "com.mysql.jdbc.Driver";
        //we know this is in target/test-classes
        //File testClassPath = (new File(this.getClass().getClassLoader().getResource("org.mortbay.jetty.jar").getPath())).getParentFile();
        File testClassPath = BaseTest.getResourceAsFile(this, "org.mortbay.jetty.jar").getParentFile();
        File driver = new File(testClassPath, "../../src/test/bad/mysql-connector-java-5.1.27-bin.jar");
        DriverLoader.load(className, driver.getAbsolutePath());
    }
}
