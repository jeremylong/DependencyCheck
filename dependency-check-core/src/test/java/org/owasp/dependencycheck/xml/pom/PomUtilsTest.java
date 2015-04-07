/*
 * Copyright 2015 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.xml.pom;

import org.owasp.dependencycheck.xml.pom.PomUtils;
import java.io.File;
import javax.xml.transform.sax.SAXSource;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.xml.pom.Model;

/**
 *
 * @author jeremy
 */
public class PomUtilsTest {

    public PomUtilsTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of readPom method, of class PomUtils.
     */
    @Test
    public void testReadPom_File() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "dwr-xml.pom");

        String expResult = "Direct Web Remoting";
        Model result = PomUtils.readPom(file);
        assertEquals(expResult, result.getName());
    }

//    /**
//     * Test of analyzePOM method, of class PomUtils.
//     */
//    @Test
//    public void testAnalyzePOM() throws Exception {
//        System.out.println("analyzePOM");
//        Dependency dependency = null;
//        File pomFile = null;
//        PomUtils instance = new PomUtils();
//        instance.analyzePOM(dependency, pomFile);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
}
