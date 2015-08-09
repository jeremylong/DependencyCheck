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
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
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
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NodePackageAnalyzer.class);

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
        final File file = dependency.getActualFile();
        String contents;
        try {
            contents = FileUtils.readFileToString(file).trim();
        } catch (IOException e) {
            throw new AnalysisException(
                    "Problem occurred while reading dependency file.", e);
        }
        try {
            JSONObject json = new JSONObject(contents);
            final EvidenceCollection productEvidence = dependency.getProductEvidence();
            final EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
            if (json.has("name")) {
                Object value = json.get("name");
                if (value instanceof String) {
                    productEvidence.addEvidence(PACKAGE_JSON, "name", (String) value, Confidence.HIGHEST);
                    vendorEvidence.addEvidence(PACKAGE_JSON, "name_project", String.format("%s_project", value), Confidence.LOW);
                } else {
                    LOGGER.warn("JSON value not string as expected: %s", value);
                }
            }
            addToEvidence(json, productEvidence, "description");
            addToEvidence(json, vendorEvidence, "author");
            addToEvidence(json, dependency.getVersionEvidence(), "version");
            dependency.setDisplayFileName(String.format("%s/%s", file.getParentFile().getName(), file.getName()));
        } catch (JSONException e) {
            LOGGER.warn("Failed to parse package.json file.", e);
        }
    }

    private void addToEvidence(JSONObject json, EvidenceCollection collection, String key) {
        if (json.has(key)) {
            Object value = json.get(key);
            if (value instanceof String) {
                collection.addEvidence(PACKAGE_JSON, key, (String) value, Confidence.HIGHEST);
            } else if (value instanceof JSONObject) {
                final JSONObject jsonObject = (JSONObject) value;
                for (String property : jsonObject.keySet()) {
                    final Object subValue = jsonObject.get(property);
                    if (subValue instanceof String) {
                        collection.addEvidence(PACKAGE_JSON,
                                String.format("%s.%s", key, property),
                                (String) subValue,
                                Confidence.HIGHEST);
                    } else {
                        LOGGER.warn("JSON sub-value not string as expected: %s");
                    }
                }
            } else {
                LOGGER.warn("JSON value not string or JSON object as expected: %s", value);
            }
        }
    }
}
