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
 * Copyright (c) 2015 Institute for Defense Analyses. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.lang.StringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

import java.util.Arrays;
import java.util.HashSet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for OpenSSLAnalyzerAnalyzer.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class OpenSSLAnalyzerTest extends BaseTest {

    /**
     * The package analyzer to test.
     */
    OpenSSLAnalyzer analyzer;

    /**
     * Setup the PtyhonPackageAnalyzer.
     *
     * @throws Exception if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        analyzer = new OpenSSLAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize();
    }

    /**
     * Cleanup any resources used.
     *
     * @throws Exception if there is a problem
     */
    @After
    public void tearDown() throws Exception {
        analyzer.close();
        analyzer = null;
    }

    /**
     * Test of getName method, of class OpenSSLAnalyzer.
     */
    @Test
    public void testGetName() {
        assertEquals("Analyzer name wrong.", "OpenSSL Source Analyzer",
                analyzer.getName());
    }

    /**
     * Test of getSupportedExtensions method, of class OpenSSLAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        final String[] expected = {"h"};
        assertEquals("Supported extensions should just have the following: "
                        + StringUtils.join(expected, ", "),
                new HashSet<String>(Arrays.asList(expected)),
                analyzer.getSupportedExtensions());
    }

    /**
     * Test of supportsExtension method, of class PythonPackageAnalyzer.
     */
    @Test
    public void testSupportsExtension() {
        assertTrue("Should support \"h\" extension.",
                analyzer.supportsExtension("h"));
    }
}
