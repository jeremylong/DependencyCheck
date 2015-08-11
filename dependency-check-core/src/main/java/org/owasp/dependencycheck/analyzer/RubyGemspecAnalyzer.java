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

import java.io.FileFilter;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Used to analyze Ruby Gem specifications and collect information that can be used to determine the associated CPE.
 * Regular expressions are used to parse the well-defined Ruby syntax that forms the specification.
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

    private static final String EMAIL = "email";
    private static final String GEMSPEC = "gemspec";

    /**
     * @return a filter that accepts files named Rakefile or matching the glob pattern, *.gemspec
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
        String contents;
        try {
            contents = FileUtils.readFileToString(dependency.getActualFile());
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }
        final Matcher matcher = GEMSPEC_BLOCK_INIT.matcher(contents);
        if (matcher.find()){
            contents = contents.substring(matcher.end());
            final String blockVariable = matcher.group(1);
            final EvidenceCollection vendor = dependency.getVendorEvidence();
            addStringEvidence(vendor, contents, blockVariable, "author", Confidence.HIGHEST);
            addListEvidence(vendor, contents, blockVariable, "authors", Confidence.HIGHEST);
            final String email = addStringEvidence(vendor, contents, blockVariable, EMAIL, Confidence.MEDIUM);
            if (email.isEmpty()) {
                addListEvidence(vendor, contents, blockVariable, EMAIL, Confidence.MEDIUM);
            }
            addStringEvidence(vendor, contents, blockVariable, "homepage", Confidence.MEDIUM);
            final EvidenceCollection product = dependency.getProductEvidence();
            final String name = addStringEvidence(product, contents, blockVariable, "name", Confidence.HIGHEST);
            if (!name.isEmpty()) {
                vendor.addEvidence(GEMSPEC, "name_project", name + "_project", Confidence.LOW);
            }
            addStringEvidence(product, contents, blockVariable, "summary", Confidence.LOW);
            addStringEvidence(dependency.getVersionEvidence(), contents, blockVariable, "version", Confidence.HIGHEST);
        }
    }

    private void addListEvidence(EvidenceCollection vendorEvidence, String contents,
                                 String blockVariable, String field, Confidence confidence) {
        final Matcher matcher = Pattern.compile(
                String.format("\\s+?%s\\.%s\\s*?=\\s*?\\[(.*?)\\]", blockVariable, field)).matcher(contents);
        if (matcher.find()) {
            final String value = matcher.group(1).replaceAll("['\"]", " ").trim();
            vendorEvidence.addEvidence(GEMSPEC, field, value, confidence);
        }
    }

    private String addStringEvidence(EvidenceCollection collection, String contents,
                                     String blockVariable, String field, Confidence confidence) {
        final Matcher matcher = Pattern.compile(
                String.format("\\s+?%s\\.%s\\s*?=\\s*?(['\"])(.*?)\\1", blockVariable, field)).matcher(contents);
        String value = "";
        if (matcher.find()){
            value = matcher.group(2);
            collection.addEvidence(GEMSPEC, field, value, confidence);
        }
        return value;
    }
}
