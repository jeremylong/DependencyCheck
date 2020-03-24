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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.List;
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
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Used to analyze Ruby Gem specifications and collect information that can be
 * used to determine the associated CPE. Regular expressions are used to parse
 * the well-defined Ruby syntax that forms the specification.
 *
 * @author Dale Visser
 */
@Experimental
@ThreadSafe
public class RubyGemspecAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.RUBY;
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RubyGemspecAnalyzer.class);
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Ruby Gemspec Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The gemspec file extension.
     */
    private static final String GEMSPEC = "gemspec";
    /**
     * The file filter containing the list of file extensions that can be
     * analyzed.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(GEMSPEC).build();
    //TODO: support Rakefile
    //= FileFilterBuilder.newInstance().addExtensions(GEMSPEC).addFilenames("Rakefile").build();

    /**
     * The name of the version file.
     */
    private static final String VERSION_FILE_NAME = "VERSION";

    /**
     * The capture group #1 is the block variable.
     */
    private static final Pattern GEMSPEC_BLOCK_INIT = Pattern.compile("Gem::Specification\\.new\\s+?do\\s+?\\|(.+?)\\|");

    /**
     * @return a filter that accepts files matching the glob pattern, *.gemspec
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
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
        return Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        String contents;
        try {
            contents = FileUtils.readFileToString(dependency.getActualFile(), Charset.defaultCharset());
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }
        final Matcher matcher = GEMSPEC_BLOCK_INIT.matcher(contents);
        if (matcher.find()) {
            contents = contents.substring(matcher.end());
            final String blockVariable = matcher.group(1);

            final String name = addStringEvidence(dependency, EvidenceType.PRODUCT, contents, blockVariable, "name", "name", Confidence.HIGHEST);
            if (!name.isEmpty()) {
                dependency.addEvidence(EvidenceType.VENDOR, GEMSPEC, "name_project", name + "_project", Confidence.LOW);
                dependency.setName(name);
            }
            final String description = addStringEvidence(dependency, EvidenceType.PRODUCT, contents, blockVariable,
                    "summary", "summary", Confidence.LOW);
            if (description != null && !description.isEmpty()) {
                dependency.setDescription(description);
            }
            addStringEvidence(dependency, EvidenceType.VENDOR, contents, blockVariable,
                    "author", "authors?", Confidence.HIGHEST);
            addStringEvidence(dependency, EvidenceType.VENDOR, contents, blockVariable,
                    "email", "emails?", Confidence.MEDIUM);
            addStringEvidence(dependency, EvidenceType.VENDOR, contents, blockVariable,
                    "homepage", "homepage", Confidence.HIGHEST);
            final String license = addStringEvidence(dependency, EvidenceType.VENDOR, contents, blockVariable,
                    "license", "licen[cs]es?", Confidence.HIGHEST);
            if (license != null && !license.isEmpty()) {
                dependency.setLicense(license);
            }
            final String value = addStringEvidence(dependency, EvidenceType.VERSION, contents,
                    blockVariable, "version", "version", Confidence.HIGHEST);
            if (value.length() < 1) {
                final String version = addEvidenceFromVersionFile(dependency, EvidenceType.VERSION, dependency.getActualFile());
                if (version != null) {
                    dependency.setVersion(version);
                }
            } else {
                dependency.setVersion(value);
            }
        }
        if (dependency.getName() != null && dependency.getVersion() != null) {
            dependency.setDisplayFileName(String.format("%s:%s", dependency.getName(), dependency.getVersion()));
        }

        try {
            final PackageURLBuilder builder = PackageURLBuilder.aPackageURL().withType("gem").withName(dependency.getName());
            if (dependency.getVersion() != null) {
                builder.withVersion(dependency.getVersion());
            }
            final PackageURL purl = builder.build();
            dependency.addSoftwareIdentifier(new PurlIdentifier(purl, Confidence.HIGHEST));
        } catch (MalformedPackageURLException ex) {
            LOGGER.debug("Unable to build package url for python", ex);
            final GenericIdentifier id;
            if (dependency.getVersion() != null) {
                id = new GenericIdentifier("gem:" + dependency.getName() + "@" + dependency.getVersion(), Confidence.HIGHEST);
            } else {
                id = new GenericIdentifier("gem:" + dependency.getName(), Confidence.HIGHEST);
            }
            dependency.addSoftwareIdentifier(id);
        }

        setPackagePath(dependency);
    }

    /**
     * Adds the specified evidence to the given evidence collection.
     *
     * @param dependency the dependency being analyzed
     * @param type the type of evidence to add
     * @param contents the evidence contents
     * @param blockVariable the variable
     * @param field the field
     * @param fieldPattern the field pattern
     * @param confidence the confidence of the evidence
     * @return the evidence string value added
     */
    private String addStringEvidence(Dependency dependency, EvidenceType type, String contents,
            String blockVariable, String field, String fieldPattern, Confidence confidence) {
        String value = "";

        //capture array value between [ ]
        final Matcher arrayMatcher = Pattern.compile(
                String.format("\\s*?%s\\.%s\\s*?=\\s*?\\[(.*?)\\]", blockVariable, fieldPattern), Pattern.CASE_INSENSITIVE).matcher(contents);
        if (arrayMatcher.find()) {
            final String arrayValue = arrayMatcher.group(1);
            value = arrayValue.replaceAll("['\"]", "").trim(); //strip quotes
        } else { //capture single value between quotes
            final Matcher matcher = Pattern.compile(
                    String.format("\\s*?%s\\.%s\\s*?=\\s*?(['\"])(.*?)\\1", blockVariable, fieldPattern), Pattern.CASE_INSENSITIVE).matcher(contents);
            if (matcher.find()) {
                value = matcher.group(2);
            }
        }
        if (value.length() > 0) {
            dependency.addEvidence(type, GEMSPEC, field, value, confidence);
        }

        return value;
    }

    /**
     * Adds evidence from the version file.
     *
     * @param dependency the dependency being analyzed
     * @param type the type of evidence to add
     * @param dependencyFile the dependency being analyzed
     * @return the version number added
     */
    private String addEvidenceFromVersionFile(Dependency dependency, EvidenceType type, File dependencyFile) {
        final File parentDir = dependencyFile.getParentFile();
        String version = null;
        int versionCount = 0;
        if (parentDir != null) {
            final File[] matchingFiles = parentDir.listFiles(new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    return name.contains(VERSION_FILE_NAME);
                }
            });
            if (matchingFiles == null) {
                return null;
            }
            for (File f : matchingFiles) {
                try {
                    final List<String> lines = FileUtils.readLines(f, Charset.defaultCharset());
                    if (lines.size() == 1) { //TODO other checking?
                        final String value = lines.get(0).trim();
                        if (version == null || !version.equals(value)) {
                            version = value;
                            versionCount++;
                        }

                        dependency.addEvidence(type, GEMSPEC, "version", value, Confidence.HIGH);
                    }
                } catch (IOException e) {
                    LOGGER.debug("Error reading gemspec", e);
                }
            }
        }
        if (versionCount == 1) {
            return version;
        }
        return null;
    }

    /**
     * Sets the package path on the dependency.
     *
     * @param dep the dependency to alter
     */
    private void setPackagePath(Dependency dep) {
        final File file = new File(dep.getFilePath());
        final String parent = file.getParent();
        if (parent != null) {
            dep.setPackagePath(parent);
        }
    }
}
