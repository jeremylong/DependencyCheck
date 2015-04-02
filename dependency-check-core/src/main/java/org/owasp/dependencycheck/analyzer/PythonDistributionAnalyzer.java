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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;

import org.apache.commons.collections.iterators.ReverseListIterator;
import org.apache.commons.io.filefilter.NameFileFilter;
import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.apache.commons.io.input.AutoCloseInputStream;
import org.apache.commons.lang.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.ExtractionException;
import org.owasp.dependencycheck.utils.ExtractionUtil;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.UrlStringUtils;

/**
 * Used to analyze a Wheel or egg distriution files, or their contents in
 * unzipped form, and collect information that can be used to determine the
 * associated CPE.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class PythonDistributionAnalyzer extends AbstractFileTypeAnalyzer {

	/**
	 * Name of egg metatdata files to analyze.
	 */
	private static final String PKG_INFO = "PKG-INFO";

	/**
	 * Name of wheel metadata files to analyze.
	 */
	private static final String METADATA = "METADATA";

	/**
	 * The logger.
	 */
	private static final Logger LOGGER = Logger
			.getLogger(PythonDistributionAnalyzer.class.getName());

	/**
	 * The count of directories created during analysis. This is used for
	 * creating temporary directories.
	 */
	private static int dirCount = 0;

	/**
	 * The name of the analyzer.
	 */
	private static final String ANALYZER_NAME = "Python Distribution Analyzer";
	/**
	 * The phase that this analyzer is intended to run in.
	 */
	private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

	/**
	 * The set of file extensions supported by this analyzer.
	 */
	private static final Set<String> EXTENSIONS = newHashSet("whl", "egg",
			"zip", METADATA, PKG_INFO);

	/**
	 * Used to match on egg archive candidate extenssions.
	 */
	private static final Pattern EGG_OR_ZIP = Pattern.compile("egg|zip");

	/**
	 * The parent directory for the individual directories per archive.
	 */
	private File tempFileLocation;

	/**
	 * Filter that detects *.dist-info files (but doesn't verify they are
	 * directories.
	 */
	private static final FilenameFilter DIST_INFO_FILTER = new SuffixFileFilter(
			".dist-info");

	/**
	 * Filter that detects files named "METADATA".
	 */
	private static final FilenameFilter EGG_INFO_FILTER = new NameFileFilter(
			"EGG-INFO");

	/**
	 * Filter that detects files named "METADATA".
	 */
	private static final FilenameFilter METADATA_FILTER = new NameFileFilter(
			METADATA);

	/**
	 * Filter that detects files named "PKG-INFO".
	 */
	private static final FilenameFilter PKG_INFO_FILTER = new NameFileFilter(
			PKG_INFO);

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
		if ("whl".equals(dependency.getFileExtension())) {
			collectMetadataFromArchiveFormat(dependency, DIST_INFO_FILTER,
					METADATA_FILTER);
		} else if (EGG_OR_ZIP.matcher(
				StringUtils.stripToEmpty(dependency.getFileExtension()))
				.matches()) {
			collectMetadataFromArchiveFormat(dependency, EGG_INFO_FILTER,
					PKG_INFO_FILTER);
		} else {
			final File actualFile = dependency.getActualFile();
			final String name = actualFile.getName();
			final boolean metadata = METADATA.equals(name);
			if (metadata || PKG_INFO.equals(name)) {
				final File parent = actualFile.getParentFile();
				final String parentName = parent.getName();
				dependency.setDisplayFileName(parentName + "/" + name);
				if (parent.isDirectory()
						&& (metadata && parentName.endsWith(".dist-info")
								|| parentName.endsWith(".egg-info") || "EGG-INFO"
									.equals(parentName))) {
					collectWheelMetadata(dependency, actualFile);
				}
			}
		}
	}

	private void collectMetadataFromArchiveFormat(Dependency dependency,
			FilenameFilter folderFilter, FilenameFilter metadataFilter)
			throws AnalysisException {
		final File temp = getNextTempDirectory();
		LOGGER.fine(String.format("%s exists? %b", temp, temp.exists()));
		try {
			ExtractionUtil.extractFilesUsingFilter(
					new File(dependency.getActualFilePath()), temp,
					metadataFilter);
		} catch (ExtractionException ex) {
			throw new AnalysisException(ex);
		}

		collectWheelMetadata(
				dependency,
				getMatchingFile(getMatchingFile(temp, folderFilter),
						metadataFilter));
	}

	/**
	 * Makes sure a usable temporary directory is available.
	 */
	@Override
	protected void initializeFileTypeAnalyzer() throws Exception {
		final File baseDir = Settings.getTempDirectory();
		tempFileLocation = File.createTempFile("check", "tmp", baseDir);
		if (!tempFileLocation.delete()) {
			final String msg = String.format(
					"Unable to delete temporary file '%s'.",
					tempFileLocation.getAbsolutePath());
			throw new AnalysisException(msg);
		}
		if (!tempFileLocation.mkdirs()) {
			final String msg = String.format(
					"Unable to create directory '%s'.",
					tempFileLocation.getAbsolutePath());
			throw new AnalysisException(msg);
		}
	}

	/**
	 * Deletes any files extracted from the Wheel during analysis.
	 */
	@Override
	public void close() {
		if (tempFileLocation != null && tempFileLocation.exists()) {
			LOGGER.log(Level.FINE, "Attempting to delete temporary files");
			final boolean success = FileUtils.delete(tempFileLocation);
			if (!success) {
				LOGGER.log(Level.WARNING,
						"Failed to delete some temporary files, see the log for more details");
			}
		}
	}

	/**
	 * Gathers evidence from the METADATA file.
	 *
	 * @param dependency
	 *            the dependency being analyzed
	 * @throws MalformedURLException
	 */
	private static void collectWheelMetadata(Dependency dependency, File file)
			throws AnalysisException {
		final InternetHeaders headers = getManifestProperties(file);
		addPropertyToEvidence(headers, dependency.getVersionEvidence(),
				"Version", Confidence.HIGHEST);
		addPropertyToEvidence(headers, dependency.getProductEvidence(), "Name",
				Confidence.HIGHEST);
		final String url = headers.getHeader("Home-page", null);
		final EvidenceCollection vendorEvidence = dependency
				.getVendorEvidence();
		if (StringUtils.isNotBlank(url)) {
			if (UrlStringUtils.isUrl(url)) {
				try {
					vendorEvidence.addEvidence(METADATA, "vendor",
							(String) (new ReverseListIterator(
									Arrays.asList(UrlStringUtils
											.extractImportantUrlData(url).get(0)
											.split(Pattern.quote("."))))).next(),
							Confidence.MEDIUM);
				} catch (MalformedURLException mue) {
					LOGGER.fine("URL didn't parse: " + mue.getMessage());
				}
			}
		}
		addPropertyToEvidence(headers, vendorEvidence, "Author", Confidence.LOW);
		final String summary = headers.getHeader("Summary", null);
		if (StringUtils.isNotBlank(summary)) {
			JarAnalyzer
					.addDescription(dependency, summary, METADATA, "summary");
		}
	}

	private static void addPropertyToEvidence(InternetHeaders headers,
			EvidenceCollection evidence, String property, Confidence confidence) {
		final String value = headers.getHeader(property, null);
		LOGGER.fine(String.format("Property: %s, Value: %s\n", property, value));
		if (StringUtils.isNotBlank(value)) {
			evidence.addEvidence(METADATA, property, value, confidence);
		}
	}

	private static final File getMatchingFile(File folder, FilenameFilter filter) {
		File result = null;
		final File[] matches = folder.listFiles(filter);
		if (null != matches && 1 == matches.length) {
			result = matches[0];
		}
		return result;
	}

	private static InternetHeaders getManifestProperties(File manifest) {
		final InternetHeaders result = new InternetHeaders();
		if (null == manifest) {
			LOGGER.fine("Manifest file not found.");
		} else {
			try {
				result.load(new AutoCloseInputStream(new BufferedInputStream(
						new FileInputStream(manifest))));
			} catch (MessagingException e) {
				LOGGER.log(Level.WARNING, e.getMessage(), e);
			} catch (FileNotFoundException e) {
				LOGGER.log(Level.WARNING, e.getMessage(), e);
			}
		}
		return result;
	}

	/**
	 * Retrieves the next temporary destingation directory for extracting an
	 * archive.
	 *
	 * @return a directory
	 * @throws AnalysisException
	 *             thrown if unable to create temporary directory
	 */
	private File getNextTempDirectory() throws AnalysisException {
		File directory;

		// getting an exception for some directories not being able to be
		// created; might be because the directory already exists?
		do {
			dirCount += 1;
			directory = new File(tempFileLocation, String.valueOf(dirCount));
		} while (directory.exists());
		if (!directory.mkdirs()) {
			throw new AnalysisException(String.format(
					"Unable to create temp directory '%s'.",
					directory.getAbsolutePath()));
		}
		return directory;
	}
}