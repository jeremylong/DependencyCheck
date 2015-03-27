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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.io.filefilter.NameFileFilter;
import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.apache.commons.io.input.AutoCloseInputStream;
import org.apache.commons.lang.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.analyzer.exception.ArchiveExtractionException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Used to load a Wheel distriution file and collect information that can be
 * used to determine the associated CPE.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class PythonDistributionAnalyzer extends AbstractFileTypeAnalyzer {

	private static final String METADATA = "METADATA";

	/**
	 * The logger.
	 */
	private static final Logger LOGGER = Logger
			.getLogger(PythonDistributionAnalyzer.class.getName());

	/**
	 * The buffer size to use when extracting files from the archive.
	 */
	private static final int BUFFER_SIZE = 4096;

	/**
	 * The count of directories created during analysis. This is used for
	 * creating temporary directories.
	 */
	private static int dirCount = 0;

	/**
	 * Constructs a new PythonDistributionAnalyzer.
	 */
	public PythonDistributionAnalyzer() {
		super();
	}

	// <editor-fold defaultstate="collapsed"
	// desc="All standard implmentation details of Analyzer">
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
	private static final Set<String> EXTENSIONS = newHashSet("whl");

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

	// </editor-fold>

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

	/**
	 * Loads a specified JAR file and collects information from the manifest and
	 * checksums to identify the correct CPE information.
	 *
	 * @param dependency
	 *            the dependency to analyze.
	 * @param engine
	 *            the engine that is scanning the dependencies
	 * @throws AnalysisException
	 *             is thrown if there is an error reading the JAR file.
	 */
	@Override
	public void analyzeFileType(Dependency dependency, Engine engine)
			throws AnalysisException {
		final File tmpWheelFolder = getNextTempDirectory();
		LOGGER.fine(String.format("%s exists? %b", tmpWheelFolder,
				tmpWheelFolder.exists()));
		extractFiles(new File(dependency.getActualFilePath()), tmpWheelFolder,
				METADATA_FILTER);
		collectWheelMetadata(dependency, tmpWheelFolder);
	}

	/**
	 * The parent directory for the individual directories per archive.
	 */
	private File tempFileLocation = null;

	/**
	 * Initializes the JarAnalyzer.
	 *
	 * @throws Exception
	 *             is thrown if there is an exception creating a temporary
	 *             directory
	 */
	@Override
	public void initializeFileTypeAnalyzer() throws Exception {
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

	private static final Pattern HOMEPAGE_VENDOR = Pattern
			.compile("^[a-zA-Z]+://.*\\.(.+)\\.[a-zA-Z]+/?.*$");

	/**
	 * Gathers evidence from the METADATA file.
	 *
	 * @param dependency
	 *            the dependency being analyzed
	 */
	private static void collectWheelMetadata(Dependency dependency,
			File wheelFolder) {
		InternetHeaders headers = getManifestProperties(wheelFolder);
		addPropertyToEvidence(headers, dependency.getVersionEvidence(),
				"Version", Confidence.HIGHEST);
		addPropertyToEvidence(headers, dependency.getProductEvidence(), "Name",
				Confidence.HIGHEST);
		String url = headers.getHeader("Home-page", null);
		EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
		if (StringUtils.isNotBlank(url)) {
			Matcher m = HOMEPAGE_VENDOR.matcher(url);
			if (m.matches()) {
				vendorEvidence.addEvidence(METADATA, "vendor", m.group(1),
						Confidence.MEDIUM);
			}
		}
		addPropertyToEvidence(headers, vendorEvidence, "Author", Confidence.LOW);
		String summary = headers.getHeader("Summary", null);
		if (StringUtils.isNotBlank(summary)) {
			JarAnalyzer
					.addDescription(dependency, summary, METADATA, "summary");
		}
	}

	private static void addPropertyToEvidence(InternetHeaders headers,
			EvidenceCollection evidence, String property, Confidence confidence) {
		String value = headers.getHeader(property, null);
		LOGGER.fine(String.format("Property: %s, Value: %s\n", property, value));
		if (StringUtils.isNotBlank(value)) {
			evidence.addEvidence(METADATA, property, value, confidence);
		}
	}

	private static final FilenameFilter DIST_INFO_FILTER = new SuffixFileFilter(
			".dist-info");

	private static final FilenameFilter METADATA_FILTER = new NameFileFilter(
			METADATA);

	private static final File getMatchingFile(File folder, FilenameFilter filter) {
		File result = null;
		File[] matches = folder.listFiles(filter);
		if (null != matches && 1 == matches.length) {
			result = matches[0];
		}
		return result;
	}

	private static InternetHeaders getManifestProperties(File wheelFolder) {
		InternetHeaders result = new InternetHeaders();
		LOGGER.fine(String.format("%s has %d entries.", wheelFolder,
				wheelFolder.list().length));
		File dist_info = getMatchingFile(wheelFolder, DIST_INFO_FILTER);
		if (null != dist_info && dist_info.isDirectory()) {
			LOGGER.fine(String.format("%s has %d entries.", dist_info,
					dist_info.list().length));
			File manifest = getMatchingFile(dist_info, METADATA_FILTER);
			LOGGER.fine(String.format("METADATA file found? %b",
					null != manifest));
			if (null != manifest) {
				try {
					result.load(new AutoCloseInputStream(
							new BufferedInputStream(new FileInputStream(
									manifest))));
				} catch (MessagingException e) {
					LOGGER.log(Level.WARNING, e.getMessage(), e);
				} catch (FileNotFoundException e) {
					LOGGER.log(Level.WARNING, e.getMessage(), e);
				}
			} else {
				LOGGER.fine(String.format("%s contents: %s", dist_info,
						StringUtils.join(dist_info.list(), ";")));
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

	/**
	 * Extracts the contents of an archive into the specified directory.
	 *
	 * @param archive
	 *            an archive file such as a WAR or EAR
	 * @param destination
	 *            a directory to extract the contents to
	 * @param filter
	 *            determines which files get extracted
	 * @throws AnalysisException
	 *             thrown if the archive is not found
	 */
	private static void extractFiles(File archive, File destination,
			FilenameFilter filter) throws AnalysisException {
		if (archive == null || destination == null) {
			return;
		}

		FileInputStream fis = null;
		try {
			fis = new FileInputStream(archive);
		} catch (FileNotFoundException ex) {
			LOGGER.log(Level.FINE, null, ex);
			throw new AnalysisException("Archive file was not found.", ex);
		}
		try {
			extractArchive(new ZipArchiveInputStream(new BufferedInputStream(
					fis)), destination, filter);
		} catch (ArchiveExtractionException ex) {
			final String msg = String.format(
					"Exception extracting archive '%s'.", archive.getName());
			LOGGER.log(Level.WARNING, msg);
			LOGGER.log(Level.FINE, null, ex);
		} finally {
			try {
				fis.close();
			} catch (IOException ex) {
				LOGGER.log(Level.FINE, null, ex);
			}
		}
	}

	/**
	 * Extracts files from an archive.
	 *
	 * @param input
	 *            the archive to extract files from
	 * @param destination
	 *            the location to write the files too
	 * @param filter
	 *            determines which files get extracted
	 * @throws ArchiveExtractionException
	 *             thrown if there is an exception extracting files from the
	 *             archive
	 */
	private static void extractArchive(ArchiveInputStream input, File destination,
			FilenameFilter filter) throws ArchiveExtractionException {
		ArchiveEntry entry;
		try {
			while ((entry = input.getNextEntry()) != null) {
				if (entry.isDirectory()) {
					final File d = new File(destination, entry.getName());
					if (!d.exists()) {
						if (!d.mkdirs()) {
							final String msg = String.format(
									"Unable to create directory '%s'.",
									d.getAbsolutePath());
							throw new AnalysisException(msg);
						}
					}
				} else {
					final File file = new File(destination, entry.getName());
					if (filter.accept(file.getParentFile(), file.getName())) {
						final String extracting = String.format(
								"Extracting '%s'", file.getPath());
						LOGGER.fine(extracting);
						BufferedOutputStream bos = null;
						FileOutputStream fos = null;
						try {
							final File parent = file.getParentFile();
							if (!parent.isDirectory()) {
								if (!parent.mkdirs()) {
									final String msg = String.format(
											"Unable to build directory '%s'.",
											parent.getAbsolutePath());
									throw new AnalysisException(msg);
								}
							}
							fos = new FileOutputStream(file);
							bos = new BufferedOutputStream(fos, BUFFER_SIZE);
							int count;
							final byte[] data = new byte[BUFFER_SIZE];
							while ((count = input.read(data, 0, BUFFER_SIZE)) != -1) {
								bos.write(data, 0, count);
							}
							bos.flush();
						} catch (FileNotFoundException ex) {
							LOGGER.log(Level.FINE, null, ex);
							final String msg = String
									.format("Unable to find file '%s'.",
											file.getName());
							throw new AnalysisException(msg, ex);
						} catch (IOException ex) {
							LOGGER.log(Level.FINE, null, ex);
							final String msg = String.format(
									"IO Exception while parsing file '%s'.",
									file.getName());
							throw new AnalysisException(msg, ex);
						} finally {
							if (bos != null) {
								try {
									bos.close();
								} catch (IOException ex) {
									LOGGER.log(Level.FINEST, null, ex);
								}
							}
							if (fos != null) {
								try {
									fos.close();
								} catch (IOException ex) {
									LOGGER.log(Level.FINEST, null, ex);
								}
							}
						}
					}
				}
			}
		} catch (IOException ex) {
			throw new ArchiveExtractionException(ex);
		} catch (Throwable ex) {
			throw new ArchiveExtractionException(ex);
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException ex) {
					LOGGER.log(Level.FINEST, null, ex);
				}
			}
		}
	}
}
