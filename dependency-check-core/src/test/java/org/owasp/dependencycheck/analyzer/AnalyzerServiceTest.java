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
package org.owasp.dependencycheck.analyzer;

import java.util.Iterator;
import java.util.Set;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class AnalyzerServiceTest {

    public AnalyzerServiceTest() {
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
     * Test of getAnalyzers method, of class AnalyzerService.
     */
    @Test
    public void testGetAnalyzers() {
        AnalyzerService instance = AnalyzerService.getInstance();
        Iterator<Analyzer> result = instance.getAnalyzers();

        boolean found = false;
        while (result.hasNext()) {
            Analyzer a = result.next();
            Set<String> e = a.getSupportedExtensions();
            if (e != null && e.contains("jar")) {
                found = true;
            }
        }
        assertTrue("JarAnalyzer loaded", found);
    }
}
