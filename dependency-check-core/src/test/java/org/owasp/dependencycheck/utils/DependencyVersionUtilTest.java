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

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DependencyVersionUtilTest {

    public DependencyVersionUtilTest() {
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

    /**
     * Test of parseVersion method, of class DependencyVersionUtil.
     */
    @Test
    public void testParseVersionFromFileName() {
        final String[] fileName = {"something-0.9.5.jar", "lib2-1.1.jar", "lib1.5r4-someflag-R26.jar",
            "lib-1.2.5-dev-20050313.jar", "testlib_V4.4.0.jar", "lib-core-2.0.0-RC1-SNAPSHOT.jar",
            "lib-jsp-2.0.1_R114940.jar", "dev-api-2.3.11_R121413.jar", "lib-api-3.7-SNAPSHOT.jar",
            "-", "", "1.3-beta", "6"};
        final String[] expResult = {"0.9.5", "1.1", "1.5.r4", "1.2.5", "4.4.0", "2.0.0.rc1",
            "2.0.1.r114940", "2.3.11.r121413", "3.7", "-", null, "1.3.beta", "6"};

        for (int i = 0; i < fileName.length; i++) {
            final DependencyVersion version = DependencyVersionUtil.parseVersion(fileName[i]);
            String result = null;
            if (version != null) {
                result = version.toString();
            }
            assertEquals("Failed extraction on \"" + fileName[i] + "\".", expResult[i], result);
        }

        String[] failingNames = {"no-version-identified.jar", "somelib-04aug2000r7-dev.jar", /*"no.version15.jar",*/
            "lib_1.0_spec-1.1.jar", "lib-api_1.0_spec-1.0.1.jar"};
        for (String failingName : failingNames) {
            final DependencyVersion version = DependencyVersionUtil.parseVersion(failingName);
            assertNull("Found version in name that should have failed \"" + failingName + "\".", version);
        }
    }
}
