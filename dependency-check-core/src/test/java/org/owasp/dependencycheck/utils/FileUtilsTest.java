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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.File;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

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
