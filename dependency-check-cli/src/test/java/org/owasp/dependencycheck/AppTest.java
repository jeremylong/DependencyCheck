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
 * Copyright (c) 2015 The OWASP Foundatio. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jeremy
 */
public class AppTest {
    /**
     * Test of ensureCanonicalPath method, of class App.
     */
    @Test
    public void testEnsureCanonicalPath() {
        String file = "../*.jar";
        App instance = new App();
        String result = instance.ensureCanonicalPath(file);
        assertFalse(result.contains(".."));
        assertTrue(result.endsWith("*.jar"));
    }

    /**
     * Test of ensureCanonicalPath method, of class App.
     */
    @Test
    public void testEnsureCanonicalPath2() {
        String file = "../some/skip/../path/file.txt";
        App instance = new App();
        String expResult = "/some/path/file.txt";
        String result = instance.ensureCanonicalPath(file);
        assertTrue("result=" + result, result.endsWith(expResult));
    }
}
