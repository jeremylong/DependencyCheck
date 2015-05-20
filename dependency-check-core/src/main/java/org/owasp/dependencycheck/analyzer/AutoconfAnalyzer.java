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

import java.io.File;
import java.io.IOException;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Used to analyze a Wheel or egg distribution files, or their contents in
 * unzipped form, and collect information that can be used to determine the
 * associated CPE.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class AutoconfAnalyzer extends AbstractFileTypeAnalyzer {

	/**
	 * Used when compiling file scanning regex patterns.
	 */
	private static final int REGEX_OPTIONS = Pattern.DOTALL
			| Pattern.CASE_INSENSITIVE;

	/**
	 * Matches assignments to version variables in Python source code.
	 */
	private static final Pattern AC_INIT_PATTERN = Pattern
			.compile(
					"AC_INIT\\(\\[{1,2}(.+?)\\]{1,2} *, *\\[{1,2}(.+?)\\]{1,2}( *, *\\[{1,2}(.+?)\\]{1,2})?",
					REGEX_OPTIONS);

	/**
	 * The name of the analyzer.
	 */
	private static final String ANALYZER_NAME = "Autoconf Analyzer";
	/**
	 * The phase that this analyzer is intended to run in.
	 */
	private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

	/**
	 * The set of file extensions supported by this analyzer.
	 */
	private static final Set<String> EXTENSIONS = newHashSet("ac");

	/**
	 * Returns a list of file EXTENSIONS supported by this analyzer.
	 *
	 * @return a list of file EXTENSIONS supported by this analyzer.
	 */
	@Override
	public Set<String> getSupportedExtensions() {
		return EXTENSIONS;
	}

	/**
	 * Returns the name of the analyzer.
	 *
	 * @return the name of the analyzer.
	 */
	@Override
	public String getName() {
		return ANALYZER_NAME;
	}

	/**
	 * Returns the phase that the analyzer is intended to run in.
	 *
	 * @return the phase that the analyzer is intended to run in.
	 */
	public AnalysisPhase getAnalysisPhase() {
		return ANALYSIS_PHASE;
	}

	/**
	 * Returns the key used in the properties file to reference the analyzer's
	 * enabled property.
	 *
	 * @return the analyzer's enabled property setting key
	 */
	@Override
	protected String getAnalyzerEnabledSettingKey() {
		return Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED;
	}

	@Override
	protected void analyzeFileType(Dependency dependency, Engine engine)
			throws AnalysisException {
		final File actualFile = dependency.getActualFile();
		final String name = actualFile.getName();
		if ("configure.ac".equals(name)) {
			final File parent = actualFile.getParentFile();
			final String parentName = parent.getName();
			dependency.setDisplayFileName(parentName + "/" + name);
			String contents = "";
			try {
				contents = FileUtils.readFileToString(actualFile).trim();
			} catch (IOException e) {
				throw new AnalysisException(
						"Problem occured while reading dependency file.", e);
			}
			if (!contents.isEmpty()) {
				final Matcher matcher = AC_INIT_PATTERN.matcher(contents);
				if (matcher.find()) {
					dependency.getProductEvidence().addEvidence(name,
							"Package", matcher.group(1), Confidence.HIGHEST);
					dependency.getVersionEvidence().addEvidence(name,
							"Package Version", matcher.group(2),
							Confidence.HIGHEST);
					dependency.getVendorEvidence().addEvidence(name,
							"Bug report address", matcher.group(4),
							Confidence.HIGH);
				}
			}
		}
	}

	@Override
	protected void initializeFileTypeAnalyzer() throws Exception {
		// TODO add useful initialization here
	}

	/**
	 * Deletes any files extracted from the Wheel during analysis.
	 */
	@Override
	public void close() {
		// TODO useful close operations here
	}
}