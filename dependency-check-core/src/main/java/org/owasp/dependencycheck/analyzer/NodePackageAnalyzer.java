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
import org.json.JSONObject;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;

import java.io.FileFilter;
import java.io.IOException;

/**
 * Used to analyze Node Package Manager (npm) package.json files, and collect information that can be used to determine
 * the associated CPE.
 *
 * @author Dale Visser <dvisser@ida.org>
 */
public class NodePackageAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Node.js Package Analyzer";

    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    public static final String PACKAGE_JSON = "package.json";
    /**
     * Filter that detects files named "package.json".
     */
    private static final FileFilter PACKAGE_JSON_FILTER =
            FileFilterBuilder.newInstance().addFilenames(PACKAGE_JSON).build();

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return PACKAGE_JSON_FILTER;
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
        return Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED;
    }

    @Override
    protected void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
        String contents;
        try {
            contents = FileUtils.readFileToString(dependency.getActualFile()).trim();
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }
        JSONObject json = new JSONObject(contents);
        final EvidenceCollection productEvidence = dependency.getProductEvidence();
        addToEvidence(json, productEvidence, "name");
        addToEvidence(json, productEvidence, "description");
        addToEvidence(json, dependency.getVendorEvidence(), "author");
        addToEvidence(json, dependency.getVersionEvidence(), "version");
    }

    private void addToEvidence(JSONObject json, EvidenceCollection productEvidence, String key) {
        if (json.has(key)) {
            Object value = json.get(key);
            if (value instanceof String) {
                productEvidence.addEvidence(PACKAGE_JSON, key, (String) value, Confidence.HIGHEST);
            } else if (value instanceof JSONObject) {
                for (String property : ((JSONObject) value).keySet()) {
                    productEvidence.addEvidence(PACKAGE_JSON,
                            String.format("%s.%s", key, property),
                            ((JSONObject) value).getString(property),
                            Confidence.HIGHEST);
                }
            }
        }
    }
}
