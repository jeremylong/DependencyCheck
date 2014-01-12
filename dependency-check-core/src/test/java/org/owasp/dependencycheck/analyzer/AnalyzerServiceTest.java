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
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.analyzer.AnalyzerService;
import org.owasp.dependencycheck.analyzer.Analyzer;
import java.util.Set;
import java.util.Iterator;
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
