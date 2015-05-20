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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashSet;

import org.apache.commons.lang.StringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 * Unit tests for PythonDistributionAnalyzer.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class AutoconfAnalyzerTest extends BaseTest {

	/**
	 * The analyzer to test.
	 */
	AutoconfAnalyzer analyzer;

	/**
	 * Correctly setup the analyzer for testing.
	 *
	 * @throws Exception
	 *             thrown if there is a problem
	 */
	@Before
	public void setUp() throws Exception {
		analyzer = new AutoconfAnalyzer();
		analyzer.setFilesMatched(true);
		analyzer.initialize();
	}

	/**
	 * Cleanup the analyzer's temp files, etc.
	 *
	 * @throws Exception
	 *             thrown if there is a problem
	 */
	@After
	public void tearDown() throws Exception {
		analyzer.close();
		analyzer = null;
	}

	/**
	 * Test of getName method, of class PythonDistributionAnalyzer.
	 */
	@Test
	public void testGetName() {
		assertEquals("Analyzer name wrong.", "Autoconf Analyzer",
				analyzer.getName());
	}

	/**
	 * Test of getSupportedExtensions method, of class
	 * PythonDistributionAnalyzer.
	 */
	@Test
	public void testGetSupportedExtensions() {
		final String[] expected = { "ac" };
		assertEquals("Supported extensions should just have the following: "
				+ StringUtils.join(expected, ", "),
				new HashSet<String>(Arrays.asList(expected)),
				analyzer.getSupportedExtensions());
	}

	/**
	 * Test of supportsExtension method, of class PythonDistributionAnalyzer.
	 */
	@Test
	public void testSupportsExtension() {
		assertTrue("Should support \"ac\" extension.",
				analyzer.supportsExtension("ac"));
	}

	/**
	 * Test of inspect method, of class PythonDistributionAnalyzer.
	 *
	 * @throws AnalysisException
	 *             is thrown when an exception occurs.
	 */
	@Test
	public void testAnalyzeConfigureAC() throws AnalysisException {
		final Dependency result = new Dependency(BaseTest.getResourceAsFile(
				this, "autoconf/configure.ac"));
		analyzer.analyze(result, null);
		assertTrue("Expected product evidence to contain \"ghostscript\".",
				result.getProductEvidence().toString().contains("ghostscript"));
		assertTrue("Expected version evidence to contain \"8.62.0\".",
				result.getVersionEvidence().toString().contains("8.62.0"));
		assertTrue("Expected vendor evidence to contain \"gnu\".",
				result.getVendorEvidence().toString().contains("gnu"));
	}
}