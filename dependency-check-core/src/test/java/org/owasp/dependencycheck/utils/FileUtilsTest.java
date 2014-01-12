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

import java.io.File;
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
public class FileUtilsTest {

    public FileUtilsTest() {
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
     * Test of getFileExtension method, of class FileUtils.
     */
    @Test
    public void testGetFileExtension() {
        String[] fileName = {"something-0.9.5.jar", "lib2-1.1.js"};
        String[] expResult = {"jar", "js"};

        for (int i = 0; i < fileName.length; i++) {
            String result = FileUtils.getFileExtension(fileName[i]);
            assertEquals("Failed extraction on \"" + fileName[i] + "\".", expResult[i], result);
        }
    }

    /**
     * Test of delete method, of class FileUtils.
     */
    @Test
    public void testDelete() throws Exception {

        File file = File.createTempFile("tmp", "deleteme");
        if (!file.exists()) {
            fail("Unable to create a temporary file.");
        }
        FileUtils.delete(file);
        assertFalse("Temporary file exists after attempting deletion", file.exists());
    }
}
