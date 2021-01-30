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
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;

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
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.NATIVE;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CMakeAnalyzer.class);

    /**
     * Used when compiling file scanning regex patterns.
     */
    private static final int REGEX_OPTIONS = Pattern.DOTALL | Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;
    /**
     * Regex to obtain the project version.
     */
    private static final Pattern PROJECT_VERSION = Pattern.compile("^\\s*set\\s*\\(\\s*VERSION\\s*\"([^\"]*)\"\\)",
            REGEX_OPTIONS);
    /**
     * Regex to obtain variables.
     */
    private static final Pattern SET_VAR_REGEX = Pattern.compile(
            "^\\s*set\\s*\\(\\s*([a-zA-Z0-9_\\-]*)\\s+\"?([a-zA-Z0-9_\\-\\.\\$\\{\\}]*)\"?\\s*\\)", REGEX_OPTIONS);
    /**
     * Regex to find inlined variables to replace them.
     */
    private static final Pattern INL_VAR_REGEX = Pattern.compile("(\\$\\s*\\{([^\\}]*)\\s*\\})", REGEX_OPTIONS);
    /**
     * Regex to extract the product information.
     */
    private static final Pattern PROJECT = Pattern.compile("^ *project *\\([ \\n]*(\\w+)[ \\n]*.*?\\)", REGEX_OPTIONS);

    /**
     * Regex to extract product and version information.
     *
     * Group 1: Product
     *
     * Group 2: Version
     */
    private static final Pattern SET_VERSION = Pattern
            .compile("^\\s*set\\s*\\(\\s*(\\w+)_version\\s+\"?([^\"\\)]*)\\s*\"?\\)", REGEX_OPTIONS);

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
            final HashMap<String, String> vars = new HashMap<>();
            collectDefinedVariables(dependency, engine, contents, vars);

            String contentsReplacer = contents;
            Matcher r = INL_VAR_REGEX.matcher(contents);
            while (r.find()) {
                boolean leastOne = false;
                if (vars.containsKey(r.group(2))) {
                    if (!vars.get(r.group(2)).contains(r.group(2))) {
                        contentsReplacer = contentsReplacer.replace(r.group(1), vars.get(r.group(2)));
                        r = INL_VAR_REGEX.matcher(contentsReplacer);
                        leastOne = true;
                    }
                }
                while (r.find()) {
                    if (vars.containsKey(r.group(2))) {
                        if (!vars.get(r.group(2)).contains(r.group(2))) {
                            contentsReplacer = contentsReplacer.replace(r.group(1), vars.get(r.group(2)));
                            r = INL_VAR_REGEX.matcher(contentsReplacer);
                            leastOne = true;
                        }
                    }
                }
                if (!leastOne) {
                    break;
                }
                r = INL_VAR_REGEX.matcher(contentsReplacer);
            }
            final String contentsReplaced = contentsReplacer;
            final Matcher m = PROJECT.matcher(contentsReplaced);
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
                dependency.setDisplayFileName(group);
            }
            if (count > 0) {
                dependency.addEvidence(EvidenceType.VENDOR, "CmakeAnalyzer", "hint", "gnu", Confidence.MEDIUM);
            }
            LOGGER.debug("Found {} matches.", count);
            final Matcher mVersion = PROJECT_VERSION.matcher(contentsReplaced);
            while (mVersion.find()) {
                LOGGER.debug(String.format(
                        "Found set version command match with %d groups: %s",
                        mVersion.groupCount(), mVersion.group(0)));
                final String group = mVersion.group(1);
                LOGGER.debug("Group 1: {}", group);
                dependency.addEvidence(EvidenceType.VERSION, name, "VERSION", group, Confidence.HIGH);
                final DependencyVersion vers = DependencyVersionUtil.parseVersion(group, true);
                if (vers != null) {
                    dependency.setVersion(vers.toString());
                }
            }

            analyzeSetVersionCommand(dependency, engine, contentsReplaced);
        }
    }

    /**
     * Collect defined CMake variables
     *
     * @param dependency the dependency being analyzed
     * @param engine the dependency-check engine
     * @param contents the version information
     * @param vars map of variable replacement tokens
     */
    private void collectDefinedVariables(Dependency dependency, Engine engine, String contents,
            HashMap<String, String> vars) {
        final Matcher m = SET_VAR_REGEX.matcher(contents);
        int count = 0;
        while (m.find()) {
            count++;
            LOGGER.debug("Found set variable command match with {} groups: {}",
                    m.groupCount(), m.group(0));
            final String name = m.group(1);
            final String value = m.group(2);
            LOGGER.debug("Group 1: {}", name);
            LOGGER.debug("Group 2: {}", value);
            vars.put(name, value);
        }
        LOGGER.debug("Found {} matches.", count);
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
            if (product.startsWith("_")) {
                product = product.substring(1);
            }
            if (count > 1) {
                currentDep = new Dependency(dependency.getActualFile(), true);
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
            if (product.toLowerCase().endsWith("lib")) {
                currentDep = new Dependency(dependency.getActualFile(), true);
                currentDep.setEcosystem(DEPENDENCY_ECOSYSTEM);
                final String filePath = String.format("%s:%s", dependency.getFilePath(), product);
                currentDep.setFilePath(filePath);

                currentDep.setSha1sum(Checksum.getSHA1Checksum(filePath));
                currentDep.setSha256sum(Checksum.getSHA256Checksum(filePath));
                currentDep.setMd5sum(Checksum.getMD5Checksum(filePath));
                engine.addDependency(currentDep);
                product = "lib" + product.toLowerCase().substring(0, product.length() - 3);
                currentDep.addEvidence(EvidenceType.PRODUCT, source, "Product", product, Confidence.MEDIUM);
                currentDep.addEvidence(EvidenceType.VENDOR, source, "Vendor", product, Confidence.MEDIUM);
                currentDep.addEvidence(EvidenceType.VERSION, source, "Version", version, Confidence.MEDIUM);
            }
            if (StringUtils.isBlank(currentDep.getName())) {
                currentDep.setName(product);
                currentDep.setDisplayFileName(product);
            }
            if (StringUtils.isBlank(currentDep.getVersion())) {
                final DependencyVersion vers = DependencyVersionUtil.parseVersion(version, true);
                if (vers != null) {
                    currentDep.setVersion(vers.toString());
                }
            }
        }
        LOGGER.debug("Found {} matches.", count);
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CMAKE_ENABLED;
    }
}
