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
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.owasp.dependencycheck.dependency.EvidenceType;
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
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "CMAKE";

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CMakeAnalyzer.class);

    /**
     * Used when compiling file scanning regex patterns.
     */
    private static final int REGEX_OPTIONS = Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;

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
    private static final Pattern SET_VERSION = Pattern.compile(
            "^ *set\\s*\\(\\s*(\\w+)_version\\s+\"?(\\d+(?:\\.\\d+)+)[\\s\"]?\\)", REGEX_OPTIONS);

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
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if an exception occurs getting an
     * instance of SHA1
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        //do nothing
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
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        final File file = dependency.getActualFile();
        final String name = file.getName();
        final String contents;
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
                LOGGER.debug("Group 1: {}", group);
                dependency.addEvidence(EvidenceType.PRODUCT, name, "Project", group, Confidence.HIGH);
                dependency.addEvidence(EvidenceType.VENDOR, name, "Project", group, Confidence.HIGH);
                dependency.setName(group);
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
            LOGGER.debug("Group 1: {}", product);
            LOGGER.debug("Group 2: {}", version);
            final String aliasPrefix = "ALIASOF_";
            if (product.startsWith(aliasPrefix)) {
                product = product.replaceFirst(aliasPrefix, "");
            }
            if (count > 1) {
                //TODO - refactor so we do not assign to the parameter (checkstyle)
                currentDep = new Dependency(dependency.getActualFile());
                currentDep.setEcosystem(DEPENDENCY_ECOSYSTEM);
                final String filePath = String.format("%s:%s", dependency.getFilePath(), product);
                currentDep.setFilePath(filePath);

                currentDep.setSha1sum(Checksum.getSHA1Checksum(filePath));
                currentDep.setSha256sum(Checksum.getSHA256Checksum(filePath));
                currentDep.setMd5sum(Checksum.getMD5Checksum(filePath));
                engine.addDependency(currentDep);
            }
            final String source = currentDep.getFileName();
            currentDep.addEvidence(EvidenceType.PRODUCT, source, "Product", product, Confidence.MEDIUM);
            currentDep.addEvidence(EvidenceType.VENDOR, source, "Vendor", product, Confidence.MEDIUM);
            currentDep.addEvidence(EvidenceType.VERSION, source, "Version", version, Confidence.MEDIUM);
            currentDep.setName(product);
            currentDep.setVersion(version);
        }
        LOGGER.debug("Found {} matches.", count);
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CMAKE_ENABLED;
    }
}
