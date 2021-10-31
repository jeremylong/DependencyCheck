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
 * Copyright (c) 2016 IBM Corporation. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.ThreadSafe;

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This analyzer is used to analyze the SWIFT Package Manager
 * (https://swift.org/package-manager/). It collects information about a package
 * from Package.swift files.
 *
 * @author Bianca Jiang (https://twitter.com/biancajiang)
 */
@Experimental
@ThreadSafe
public class SwiftPackageManagerAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SwiftPackageManagerAnalyzer.class);

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.IOS;

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "SWIFT Package Manager Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The file name to scan.
     */
    public static final String SPM_FILE_NAME = "Package.swift";

    /**
     * Filter that detects files named "Package.swift".
     */
    private static final FileFilter SPM_FILE_FILTER = FileFilterBuilder.newInstance().addFilenames(SPM_FILE_NAME).build();

    /**
     * The capture group #1 is the block variable. e.g. "import
     * PackageDescription let package = Package( name: "Gloss" )"
     */
    private static final Pattern SPM_BLOCK_PATTERN = Pattern.compile("let[^=]+=\\s*Package\\s*\\(\\s*([^)]*)\\s*\\)", Pattern.DOTALL);

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return SPM_FILE_FILTER;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) {
        // NO-OP
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
    @Override
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
        return Settings.KEYS.ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            analyzeSpmFileDependency(dependency);

        } catch (IOException ex) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file: " + dependency.getActualFilePath(), ex);
        }
    }

    /**
     * Analyzes the SPM file and adds the evidence to the dependency.
     *
     * @param dependency the dependency
     * @throws IOException thrown if there is an error analyzing the `podspec`
     * file
     */
    private void analyzeSpmFileDependency(Dependency dependency)
            throws AnalysisException, IOException {
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);

        final String contents = FileUtils.readFileToString(dependency.getActualFile(), Charset.defaultCharset());

        final Matcher matcher = SPM_BLOCK_PATTERN.matcher(contents);
        if (matcher.find()) {
            final String packageDescription = matcher.group(1);
            if (packageDescription.isEmpty()) {
                return;
            }

            // TODO SPM is currently under development for SWIFT 3. Its current metadata includes
            // package name and dependencies.
            // Future interesting metadata: version, license, homepage, author, summary,
            // etc.
            final String name = addStringEvidence(dependency, EvidenceType.PRODUCT, packageDescription, "name", "name", Confidence.HIGHEST);
            if (name != null && !name.isEmpty()) {
                dependency.addEvidence(EvidenceType.VENDOR, SPM_FILE_NAME, "name_project", name, Confidence.HIGHEST);
                dependency.setName(name);
            } else {
                // if we can't get the name from the meta, then assume the name is the name of
                // the parent folder containing the package.swift file.
                dependency.setName(dependency.getActualFile().getParentFile().getName());
            }
            if (dependency.getVersion() != null && !dependency.getVersion().isEmpty()) {
                dependency.setDisplayFileName(String.format("%s:%s", dependency.getName(), dependency.getVersion()));
            } else {
                dependency.setDisplayFileName(dependency.getName());
            }

            try {
                final PackageURLBuilder builder = PackageURLBuilder.aPackageURL().withType("swift").withName(dependency.getName());
                if (dependency.getVersion() != null) {
                    builder.withVersion(dependency.getVersion());
                }
                final PackageURL purl = builder.build();
                dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
            } catch (MalformedPackageURLException ex) {
                LOGGER.debug("Unable to build package url for swift", ex);
                final GenericIdentifier id;
                if (dependency.getVersion() != null) {
                    id = new GenericIdentifier("swift:" + dependency.getName() + "@" + dependency.getVersion(), Confidence.HIGHEST);
                } else {
                    id = new GenericIdentifier("swift:" + dependency.getName(), Confidence.HIGHEST);
                }
                dependency.addSoftwareIdentifier(id);
            }
        }
        setPackagePath(dependency);
    }

    /**
     * Extracts evidence from the package description and adds it to the given
     * evidence collection.
     *
     * @param dependency the dependency being analyzed
     * @param type the type of evidence to add
     * @param packageDescription the text to extract evidence from
     * @param field the name of the field being searched for
     * @param fieldPattern the field pattern within the contents to search for
     * @param confidence the confidence level of the evidence if found
     * @return the string that was added as evidence
     */
    private String addStringEvidence(Dependency dependency, EvidenceType type,
            String packageDescription, String field, String fieldPattern, Confidence confidence) {
        String value = "";

        final Matcher matcher = Pattern.compile(
                String.format("%s *:\\s*\"([^\"]*)", fieldPattern), Pattern.DOTALL).matcher(packageDescription);
        if (matcher.find()) {
            value = matcher.group(1);
        }

        if (value != null) {
            value = value.trim();
            if (value.length() > 0) {
                dependency.addEvidence(type, SPM_FILE_NAME, field, value, confidence);
            }
        }
        return value;
    }

    /**
     * Sets the package path on the given dependency.
     *
     * @param dep the dependency to update
     */
    private void setPackagePath(Dependency dep) {
        final File file = new File(dep.getFilePath());
        final String parent = file.getParent();
        if (parent != null) {
            dep.setPackagePath(parent);
        }
    }
}
