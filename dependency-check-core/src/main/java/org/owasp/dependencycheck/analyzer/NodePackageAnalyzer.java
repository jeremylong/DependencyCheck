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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.util.Map;
import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import org.owasp.dependencycheck.exception.InitializationException;

/**
 * Used to analyze Node Package Manager (npm) package.json files, and collect
 * information that can be used to determine the associated CPE.
 *
 * @author Dale Visser
 */
@Experimental
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

    /**
     * The file name to scan.
     */
    public static final String PACKAGE_JSON = "package.json";
    /**
     * Filter that detects files named "package.json".
     */
    private static final FileFilter PACKAGE_JSON_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(PACKAGE_JSON).build();

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
    protected void initializeFileTypeAnalyzer() throws InitializationException {
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
        return Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final File file = dependency.getActualFile();
        if (!file.isFile() || file.length()==0) {
            return;
        }
        try (JsonReader jsonReader = Json.createReader(FileUtils.openInputStream(file))) {
            final JsonObject json = jsonReader.readObject();
            final EvidenceCollection productEvidence = dependency.getProductEvidence();
            final EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
            if (json.containsKey("name")) {
                final Object value = json.get("name");
                if (value instanceof JsonString) {
                    final String valueString = ((JsonString) value).getString();
                    productEvidence.addEvidence(PACKAGE_JSON, "name", valueString, Confidence.HIGHEST);
                    vendorEvidence.addEvidence(PACKAGE_JSON, "name_project", String.format("%s_project", valueString), Confidence.LOW);
                } else {
                    LOGGER.warn("JSON value not string as expected: {}", value);
                }
            }
            addToEvidence(json, productEvidence, "description");
            addToEvidence(json, vendorEvidence, "author");
            addToEvidence(json, dependency.getVersionEvidence(), "version");
            dependency.setDisplayFileName(String.format("%s/%s", file.getParentFile().getName(), file.getName()));
        } catch (JsonException e) {
            LOGGER.warn("Failed to parse package.json file.", e);
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }
    }

    /**
     * Adds information to an evidence collection from the node json
     * configuration.
     *
     * @param json information from node.js
     * @param collection a set of evidence about a dependency
     * @param key the key to obtain the data from the json information
     */
    private void addToEvidence(JsonObject json, EvidenceCollection collection, String key) {
        if (json.containsKey(key)) {
            final JsonValue value = json.get(key);
            if (value instanceof JsonString) {
                collection.addEvidence(PACKAGE_JSON, key, ((JsonString) value).getString(), Confidence.HIGHEST);
            } else if (value instanceof JsonObject) {
                final JsonObject jsonObject = (JsonObject) value;
                for (final Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {
                    final String property = entry.getKey();
                    final JsonValue subValue = entry.getValue();
                    if (subValue instanceof JsonString) {
                        collection.addEvidence(PACKAGE_JSON,
                                String.format("%s.%s", key, property),
                                ((JsonString) subValue).getString(),
                                Confidence.HIGHEST);
                    } else {
                        LOGGER.warn("JSON sub-value not string as expected: {}", subValue);
                    }
                }
            } else {
                LOGGER.warn("JSON value not string or JSON object as expected: {}", value);
            }
        }
    }
}
