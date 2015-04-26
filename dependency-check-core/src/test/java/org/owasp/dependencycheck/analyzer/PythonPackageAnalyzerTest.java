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
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;

/**
 * Unit tests for PythonPackageAnalyzer.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class PythonPackageAnalyzerTest extends BaseTest {

	/**
	 * Test of getName method, of class PythonPackageAnalyzer.
	 */
	@Test
	public void testGetName() {
		assertEquals("Analyzer name wrong.", "Python Distribution Analyzer",
				new PythonDistributionAnalyzer().getName());
	}

	/**
	 * Test of getSupportedExtensions method, of class PythonPackageAnalyzer.
	 */
	@Test
	public void testGetSupportedExtensions() {
		final String[] expected = { "py" };
		assertEquals("Supported extensions should just have the following: "
				+ StringUtils.join(expected, ", "),
				new HashSet<String>(Arrays.asList(expected)),
				new PythonPackageAnalyzer().getSupportedExtensions());
	}

	/**
	 * Test of supportsExtension method, of class PythonPackageAnalyzer.
	 */
	@Test
	public void testSupportsExtension() {
		assertTrue("Should support \"py\" extension.",
				new PythonPackageAnalyzer().supportsExtension("py"));
	}

	@Test
	public void testAnalyzeSourceMetadata() throws AnalysisException {
		PythonDistributionAnalyzerTest.eggtestAssertions(this,
				"python/eggtest/__init__.py", new PythonPackageAnalyzer());
	}
}