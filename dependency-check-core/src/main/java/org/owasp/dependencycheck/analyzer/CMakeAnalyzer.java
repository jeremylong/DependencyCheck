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

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.owasp.dependencycheck.exception.InitializationException;

/**
 * <p>
 * Used to analyze CMake build files, and collect information that can be used
 * to determine the associated CPE.</p>
 * <p>
 * Note: This analyzer catches straightforward invocations of the project
 * command, plus some other observed patterns of version inclusion in real CMake
 * projects. Many projects make use of older versions of CMake and/or use custom
 * "homebrew" ways to insert version information. Hopefully as the newer CMake
 * call pattern grows in usage, this analyzer allow more CPEs to be
 * identified.</p>
 *
 * @author Dale Visser
 */
@Experimental
public class CMakeAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CMakeAnalyzer.class);

    /**
     * Used when compiling file scanning regex patterns.
     */
    private static final int REGEX_OPTIONS = Pattern.DOTALL
            | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;

    /**
     * Regex to extract the product information.
     */
    private static final Pattern PROJECT = Pattern.compile(
            "^ *project *\\([ \\n]*(\\w+)[ \\n]*.*?\\)", REGEX_OPTIONS);

    /**
     * Regex to extract product and version information.
     *
     * Group 1: Product
     *
     * Group 2: Version
     */
    private static final Pattern SET_VERSION = Pattern
            .compile(
                    "^ *set\\s*\\(\\s*(\\w+)_version\\s+\"?(\\d+(?:\\.\\d+)+)[\\s\"]?\\)",
                    REGEX_OPTIONS);

    /**
     * Detects files that can be analyzed.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(".cmake")
            .addFilenames("CMakeLists.txt").build();

    /**
     * Returns the name of the CMake analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return "CMake Analyzer";
    }

    /**
     * Tell that we are used for information collection.
     *
     * @return INFORMATION_COLLECTION
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * Returns the set of supported file extensions.
     *
     * @return the set of supported file extensions
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Initializes the analyzer.
     *
     * @throws InitializationException thrown if an exception occurs getting an
     * instance of SHA1
     */
    @Override
    protected void initializeFileTypeAnalyzer() throws InitializationException {
        try {
            getSha1MessageDigest();
        } catch (IllegalStateException ex) {
            setEnabled(false);
            throw new InitializationException("Unable to create SHA1 MessageDigest", ex);
        }
    }

    /**
     * Analyzes python packages and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine the engine being used to perform the scan
     * @throws AnalysisException thrown if there is an unrecoverable error
     * analyzing the dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {
        final File file = dependency.getActualFile();
        final String parentName = file.getParentFile().getName();
        final String name = file.getName();
        dependency.setDisplayFileName(String.format("%s%c%s", parentName, File.separatorChar, name));
        String contents;
        try {
            contents = FileUtils.readFileToString(file, Charset.defaultCharset()).trim();
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }

        if (StringUtils.isNotBlank(contents)) {
            final Matcher m = PROJECT.matcher(contents);
            int count = 0;
            while (m.find()) {
                count++;
                LOGGER.debug(String.format(
                        "Found project command match with %d groups: %s",
                        m.groupCount(), m.group(0)));
                final String group = m.group(1);
                LOGGER.debug("Group 1: " + group);
                dependency.getProductEvidence().addEvidence(name, "Project",
                        group, Confidence.HIGH);
            }
            LOGGER.debug("Found {} matches.", count);
            analyzeSetVersionCommand(dependency, engine, contents);
        }
    }

    /**
     * Extracts the version information from the contents. If more then one
     * version is found additional dependencies are added to the dependency
     * list.
     *
     * @param dependency the dependency being analyzed
     * @param engine the dependency-check engine
     * @param contents the version information
     */
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(
            value = "DM_DEFAULT_ENCODING",
            justification = "Default encoding is only used if UTF-8 is not available")
    private void analyzeSetVersionCommand(Dependency dependency, Engine engine, String contents) {
        Dependency currentDep = dependency;

        final Matcher m = SET_VERSION.matcher(contents);
        int count = 0;
        while (m.find()) {
            count++;
            LOGGER.debug("Found project command match with {} groups: {}",
                    m.groupCount(), m.group(0));
            String product = m.group(1);
            final String version = m.group(2);
            LOGGER.debug("Group 1: " + product);
            LOGGER.debug("Group 2: " + version);
            final String aliasPrefix = "ALIASOF_";
            if (product.startsWith(aliasPrefix)) {
                product = product.replaceFirst(aliasPrefix, "");
            }
            if (count > 1) {
                //TODO - refactor so we do not assign to the parameter (checkstyle)
                currentDep = new Dependency(dependency.getActualFile());
                currentDep.setDisplayFileName(String.format("%s:%s", dependency.getDisplayFileName(), product));
                final String filePath = String.format("%s:%s", dependency.getFilePath(), product);
                currentDep.setFilePath(filePath);

                byte[] path;
                try {
                    path = filePath.getBytes("UTF-8");
                } catch (UnsupportedEncodingException ex) {
                    path = filePath.getBytes();
                }
                final MessageDigest sha1 = getSha1MessageDigest();
                currentDep.setSha1sum(Checksum.getHex(sha1.digest(path)));
                engine.getDependencies().add(currentDep);
            }
            final String source = currentDep.getDisplayFileName();
            currentDep.getProductEvidence().addEvidence(source, "Product",
                    product, Confidence.MEDIUM);
            currentDep.getVersionEvidence().addEvidence(source, "Version",
                    version, Confidence.MEDIUM);
        }
        LOGGER.debug(String.format("Found %d matches.", count));
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CMAKE_ENABLED;
    }

    /**
     * Returns the sha1 message digest.
     *
     * @return the sha1 message digest
     */
    private MessageDigest getSha1MessageDigest() {
        try {
            return MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error(e.getMessage());
            throw new IllegalStateException("Failed to obtain the SHA1 message digest.", e);
        }
    }
}
