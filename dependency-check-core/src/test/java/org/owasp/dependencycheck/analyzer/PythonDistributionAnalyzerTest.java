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
 * Copyright (c) 2012 Dale Visser. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashSet;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;

/**
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class PythonDistributionAnalyzerTest extends BaseTest {

	/**
	 * Test of inspect method, of class JarAnalyzer.
	 *
	 * @throws Exception
	 *             is thrown when an exception occurs.
	 */
	@Test
	public void testAnalyzeWheel() throws AnalysisException {
		djangoAssertions(new Dependency(BaseTest.getResourceAsFile(this,
				"Django-1.7.2-py2.py3-none-any.whl")));
	}

	/**
	 * Test of inspect method, of class JarAnalyzer.
	 *
	 * @throws Exception
	 *             is thrown when an exception occurs.
	 */
	@Test
	public void testAnalyzeSitePackage() throws AnalysisException {
		final Dependency result = new Dependency(BaseTest.getResourceAsFile(
				this, "site-packages/Django-1.7.2.dist-info/METADATA"));
		djangoAssertions(result);
		assertEquals("Django-1.7.2.dist-info/METADATA",
				result.getDisplayFileName());
	}

	private void djangoAssertions(final Dependency result)
			throws AnalysisException {
		new PythonDistributionAnalyzer().analyze(result, null);
		assertTrue("Expected vendor evidence to contain \"djangoproject\".",
				result.getVendorEvidence().toString().contains("djangoproject"));
		boolean found = false;
		for (final Evidence e : result.getVersionEvidence()) {
			if ("Version".equals(e.getName()) && "1.7.2".equals(e.getValue())) {
				found = true;
				break;
			}
		}
		assertTrue("Version 1.7.2 not found in Django dependency.", found);
	}

	@Test
	public void testAnalyzeEggInfo() throws AnalysisException {
		final Dependency result = new Dependency(BaseTest.getResourceAsFile(
				this, "site-packages/eggutils-0.0.2-py2.7.egg-info/PKG-INFO"));
		new PythonDistributionAnalyzer().analyze(result, null);
		assertTrue("Expected vendor evidence to contain \"python\".", result
				.getVendorEvidence().toString().contains("python"));
		boolean found = false;
		for (final Evidence e : result.getVersionEvidence()) {
			if ("Version".equals(e.getName()) && "0.0.2".equals(e.getValue())) {
				found = true;
				break;
			}
		}
		assertTrue("Version 0.0.2 not found in eggutils dependency.", found);
	}

	/**
	 * Test of getSupportedExtensions method, of class JarAnalyzer.
	 */
	@Test
	public void testGetSupportedExtensions() {
		assertEquals(
				"Supported extensions should just be \"whl\", \"METADATA\" and \"PKG-INFO\".",
				new HashSet<String>(Arrays
						.asList("whl", "METADATA", "PKG-INFO")),
				new PythonDistributionAnalyzer().getSupportedExtensions());
	}

	/**
	 * Test of getName method, of class PythonDistributionAnalyzer.
	 */
	@Test
	public void testGetName() {
		assertEquals("Analyzer name wrong.", "Python Distribution Analyzer",
				new PythonDistributionAnalyzer().getName());
	}

	/**
	 * Test of supportsExtension method, of class PythonDistributionAnalyzer.
	 */
	@Test
	public void testSupportsExtension() {
		final PythonDistributionAnalyzer analyzer = new PythonDistributionAnalyzer();
		assertTrue("Should support \"whl\" extension.",
				analyzer.supportsExtension("whl"));
		assertTrue("Should support \"METADATA\" extension.",
				analyzer.supportsExtension("METADATA"));
		assertTrue("Should support \"METADATA\" extension.",
				analyzer.supportsExtension("PKG-INFO"));
	}
}