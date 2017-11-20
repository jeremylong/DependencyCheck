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
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import org.owasp.dependencycheck.Engine.Mode;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.InvalidSettingException;

/**
 * Used to analyze Node Package Manager (npm) package.json files, and collect
 * information that can be used to determine the associated CPE.
 *
 * @author Dale Visser
 */
@ThreadSafe
public class NodePackageAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NodePackageAnalyzer.class);
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "npm";
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

    /**
     * Performs validation on the configuration to ensure that the correct
     * analyzers are in place.
     *
     * @param engine the dependency-check engine
     * @throws InitializationException thrown if there is a configuration error
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        if (engine.getMode() != Mode.EVIDENCE_COLLECTION) {
            try {
                final Settings settings = engine.getSettings();
                final String[] tmp = settings.getArray(Settings.KEYS.ECOSYSTEM_SKIP_NVDCVE);
                if (tmp != null) {
                    final List<String> skipEcosystems = Arrays.asList(tmp);
                    if (skipEcosystems.contains(DEPENDENCY_ECOSYSTEM)
                            && !settings.getBoolean(Settings.KEYS.ANALYZER_NSP_PACKAGE_ENABLED)) {
                        LOGGER.debug("NodePackageAnalyzer enabled without a corresponding vulnerability analyzer");
                        final String msg = "Invalid Configuration: enabling the Node Package Analyzer without "
                                + "using the NSP Analyzer is not supported.";
                        throw new InitializationException(msg);
                    } else if (!skipEcosystems.contains(DEPENDENCY_ECOSYSTEM)) {
                        LOGGER.warn("Using the NVD CVE Analyzer with Node.js can result in many false positives.");
                    }
                }
            } catch (InvalidSettingException ex) {
                throw new InitializationException("Unable to read configuration settings", ex);
            }
        }
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
        dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        final File file = dependency.getActualFile();
        if (!file.isFile() || file.length() == 0) {
            return;
        }
        try (JsonReader jsonReader = Json.createReader(FileUtils.openInputStream(file))) {
            final JsonObject json = jsonReader.readObject();

            gatherEvidence(json, dependency);

        } catch (JsonException e) {
            LOGGER.warn("Failed to parse package.json file.", e);
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }
    }

    /**
     * Collects evidence from the given JSON for the associated dependency.
     *
     * @param json the JSON that contains the evidence to collect
     * @param dependency the dependency to add the evidence too
     */
    public static void gatherEvidence(final JsonObject json, Dependency dependency) {
        if (json.containsKey("name")) {
            final Object value = json.get("name");
            if (value instanceof JsonString) {
                final String valueString = ((JsonString) value).getString();
                dependency.setName(valueString);
                dependency.setPackagePath(valueString);
                dependency.addEvidence(EvidenceType.PRODUCT, PACKAGE_JSON, "name", valueString, Confidence.HIGHEST);
                dependency.addEvidence(EvidenceType.VENDOR, PACKAGE_JSON, "name", valueString, Confidence.HIGH);
            } else {
                LOGGER.warn("JSON value not string as expected: {}", value);
            }
        }
        addToEvidence(dependency, EvidenceType.PRODUCT, json, "description");
        addToEvidence(dependency, EvidenceType.VENDOR, json, "author");
        final String version = addToEvidence(dependency, EvidenceType.VERSION, json, "version");
        if (version != null) {
            dependency.setVersion(version);
            dependency.addIdentifier("npm", String.format("%s:%s", dependency.getName(), version), null, Confidence.HIGHEST);
        }

        // Adds the license if defined in package.json
        if (json.containsKey("license")) {
            final Object value = json.get("license");
            if (value instanceof JsonString) {
                dependency.setLicense(json.getString("license"));
            } else {
                dependency.setLicense(json.getJsonObject("license").getString("type"));
            }
        }
    }

    /**
     * Adds information to an evidence collection from the node json
     * configuration.
     *
     * @param dep the dependency to add the evidence
     * @param t the type of evidence to add
     * @param json information from node.js
     * @return the actual string set into evidence
     * @param key the key to obtain the data from the json information
     */
    private static String addToEvidence(Dependency dep, EvidenceType t, JsonObject json, String key) {
        String evidenceStr = null;
        if (json.containsKey(key)) {
            final JsonValue value = json.get(key);
            if (value instanceof JsonString) {
                evidenceStr = ((JsonString) value).getString();
                dep.addEvidence(t, PACKAGE_JSON, key, evidenceStr, Confidence.HIGHEST);
            } else if (value instanceof JsonObject) {
                final JsonObject jsonObject = (JsonObject) value;
                for (final Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {
                    final String property = entry.getKey();
                    final JsonValue subValue = entry.getValue();
                    if (subValue instanceof JsonString) {
                        evidenceStr = ((JsonString) subValue).getString();
                        dep.addEvidence(t, PACKAGE_JSON,
                                String.format("%s.%s", key, property),
                                evidenceStr,
                                Confidence.HIGHEST);
                    } else {
                        LOGGER.warn("JSON sub-value not string as expected: {}", subValue);
                    }
                }
            } else {
                LOGGER.warn("JSON value not string or JSON object as expected: {}", value);
            }
        }
        return evidenceStr;
    }
}
