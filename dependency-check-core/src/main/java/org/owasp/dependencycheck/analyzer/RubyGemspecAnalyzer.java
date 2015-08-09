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
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Used to analyze Node Package Manager (npm) package.json files, and collect information that can be used to determine
 * the associated CPE.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class RubyGemspecAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Ruby Gemspec Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    private static final FileFilter FILTER =
            FileFilterBuilder.newInstance().addExtensions("gemspec").addFilenames("Rakefile").build();
    private static final String AUTHORS = "authors";
    private static final String NAME = "name";
    private static final String EMAIL = "email";
    private static final String HOMEPAGE = "homepage";
    private static final String GEMSPEC = "gemspec";
    private static final String VERSION = "version";

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    @Override
    protected void initializeFileTypeAnalyzer() throws Exception {
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
     * Returns the key used in the properties file to reference the analyzer's enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED;
    }

    /**
     * The capture group #1 is the block variable.
     */
    private static final Pattern GEMSPEC_BLOCK_INIT =
            Pattern.compile("Gem::Specification\\.new\\s+?do\\s+?\\|(.+?)\\|");

    @Override
    protected void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
        final File file = dependency.getActualFile();
        String contents;
        try {
            contents = FileUtils.readFileToString(file).trim();
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }
        Matcher matcher = GEMSPEC_BLOCK_INIT.matcher(contents);
        if (matcher.find()){
            final int blockStart = matcher.end();
            final String blockVariable = matcher.group(1);
            final EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
            addListEvidence(vendorEvidence, contents, blockStart, blockVariable, AUTHORS, Confidence.HIGHEST);
            String name = addStringEvidence(
                    dependency.getProductEvidence(), contents, blockStart, blockVariable, NAME, Confidence.HIGHEST);
            if (!name.isEmpty()) {
                vendorEvidence.addEvidence(GEMSPEC, "name_project", name + "_project", Confidence.LOW);
            }
            String email = addStringEvidence(vendorEvidence, contents, blockStart, blockVariable, EMAIL, Confidence.MEDIUM);
            if (email.isEmpty()) {
                addListEvidence(vendorEvidence, contents, blockStart, blockVariable, EMAIL, Confidence.MEDIUM);
            }
            addStringEvidence(vendorEvidence, contents, blockStart, blockVariable, HOMEPAGE, Confidence.MEDIUM);
            addStringEvidence(
                    dependency.getVersionEvidence(), contents, blockStart, blockVariable, VERSION, Confidence.HIGHEST);
        }
    }

    private void addListEvidence(EvidenceCollection vendorEvidence, String contents, int blockStart,
                                 String blockVariable, String field, Confidence confidence) {
        final Matcher matcher = Pattern.compile(
                String.format("\\s+?%s\\.%s\\s*?=\\s*?\\[(.*?)\\]", blockVariable, field)).matcher(contents);
        if (matcher.find(blockStart)) {
            final String value = matcher.group(1).replaceAll("['\"]", " ").trim();
            vendorEvidence.addEvidence(GEMSPEC, field, value, confidence);
        }
    }

    private String addStringEvidence(EvidenceCollection collection, String contents, int blockStart,
                                     String blockVariable, String field, Confidence confidence) {
        final Matcher matcher = Pattern.compile(
                String.format("\\s+?%s\\.%s\\s*?=\\s*?(['\"])(.*?)\\1", blockVariable, field)).matcher(contents);
        String value = "";
        if (matcher.find(blockStart)){
            value = matcher.group(2);
            collection.addEvidence(GEMSPEC, field, value, confidence);
        }
        return value;
    }
}
