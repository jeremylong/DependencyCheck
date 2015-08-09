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
    public static final String AUTHORS = "authors";
    public static final String NAME = "name";
    public static final String EMAIL = "email";
    public static final String HOMEPAGE = "homepage";
    public static final String GEMSPEC = "gemspec";
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
     * Used when compiling file scanning regex patterns.
     */
    private static final int REGEX_OPTIONS = Pattern.DOTALL | Pattern.CASE_INSENSITIVE;

    /**
     * The capture group #1 is the block variable.
     */
    private static final Pattern GEMSPEC_BLOCK_INIT =
            Pattern.compile("Gem::Specification\\.new\\s+?do\\s+?\\|(.+?)\\|");

    /**
     * Utility function to create a regex pattern matcher. Group 1 captures the choice of quote character.
     * Group 2 captures the string literal.
     *
     * @param blockVariable the gemspec block variable (usually 's')
     * @param field the gemspec field name to capture
     * @return the compiled Pattern
     */
    private static Pattern compileStringAssignPattern(String blockVariable, String field) {
        return Pattern.compile(String.format("\\s+?%s\\.%s\\s*?=\\s*?(['\"])(.*?)\\1", blockVariable, field));
    }

    /**
     * Utility function to create a regex pattern matcher. Group 1 captures the list literal.
     *
     * @param blockVariable the gemspec block variable (usually 's')
     * @param field the gemspec field name to capture
     */
    private static Pattern compileListAssignPattern(String blockVariable, String field) {
        return Pattern.compile(
                String.format("\\s+?%s\\.%s\\s*?=\\s*?\\[(.*?)\\]", blockVariable, field),
                REGEX_OPTIONS);
    }

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
            final int startAt = matcher.end();
            final String blockVariable = matcher.group(1);
            final EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
            matcher = compileListAssignPattern(blockVariable, AUTHORS).matcher(contents);
            if (matcher.find(startAt)) {
                final String authors = matcher.group(1).replaceAll("['\"]", " ").trim();
                vendorEvidence.addEvidence(GEMSPEC, AUTHORS, authors, Confidence.HIGHEST);
            }
            matcher = compileStringAssignPattern(blockVariable, NAME).matcher(contents);
            if (matcher.find(startAt)) {
                final String name = matcher.group(2);
                dependency.getProductEvidence().addEvidence(GEMSPEC, NAME, name, Confidence.HIGHEST);
                vendorEvidence.addEvidence(GEMSPEC, "name_project", name + "_project", Confidence.LOW);
            }
            matcher = compileStringAssignPattern(blockVariable, EMAIL).matcher(contents);
            if (matcher.find(startAt)) {
                final String email = matcher.group(2);
                vendorEvidence.addEvidence(GEMSPEC, EMAIL, email, Confidence.MEDIUM);
            } else {
                matcher = compileListAssignPattern(blockVariable, EMAIL).matcher(contents);
                final String email = matcher.group(1).replaceAll("['\"]", " ").trim();
                vendorEvidence.addEvidence(GEMSPEC, EMAIL, email, Confidence.MEDIUM);
            }
            matcher = compileStringAssignPattern(blockVariable, HOMEPAGE).matcher(contents);
            if (matcher.find(startAt)){
                final String homepage = matcher.group(2);
                vendorEvidence.addEvidence(GEMSPEC, HOMEPAGE, homepage, Confidence.MEDIUM);
            }
            matcher = compileStringAssignPattern(blockVariable, VERSION).matcher(contents);
            if (matcher.find(startAt)){
                final String version = matcher.group(2);
                dependency.getVersionEvidence().addEvidence(GEMSPEC, VERSION, version, Confidence.HIGHEST);
            }
        }
    }
}
