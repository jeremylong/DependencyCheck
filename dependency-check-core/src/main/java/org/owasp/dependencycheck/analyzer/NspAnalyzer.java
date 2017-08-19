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
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nsp.Advisory;
import org.owasp.dependencycheck.data.nsp.NspSearch;
import org.owasp.dependencycheck.data.nsp.SanitizePackage;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;

/**
 * Used to analyze Node Package Manager (npm) package.json files via Node
 * Security Platform (nsp).
 *
 * @author Steve Springett
 */
public class NspAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NspAnalyzer.class);

    /**
     * The default URL to the NSP check API.
     */
    public static final String DEFAULT_URL = "https://api.nodesecurity.io/check";

    /**
     * The file name to scan.
     */
    private static final String PACKAGE_JSON = "package.json";

    /**
     * Filter that detects files named "package.json".
     */
    private static final FileFilter PACKAGE_JSON_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(PACKAGE_JSON).build();

    /**
     * The NSP Searcher.
     */
    private NspSearch searcher;

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
     * Initializes the analyzer once before any analysis is performed.
     *
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    public void initializeFileTypeAnalyzer() throws InitializationException {
        LOGGER.debug("Initializing {}", getName());
        final String searchUrl = Settings.getString(Settings.KEYS.ANALYZER_NSP_URL, DEFAULT_URL);
        try {
            searcher = new NspSearch(new URL(searchUrl));
        } catch (MalformedURLException ex) {
            setEnabled(false);
            throw new InitializationException("The configured URL to Node Security Platform is malformed: " + searchUrl, ex);
        }
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return "Node Security Platform Analyzer";
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
    }

    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.x
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NSP_PACKAGE_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final File file = dependency.getActualFile();
        if (!file.isFile() || file.length()==0) {
            return;
        }
        try (JsonReader jsonReader = Json.createReader(FileUtils.openInputStream(file))) {

            // Do not scan the node_modules directory
            if (file.getCanonicalPath().contains(File.separator + "node_modules" + File.separator)) {
                LOGGER.debug("Skipping analysis of node module: " + file.getCanonicalPath());
                return;
            }

            // Retrieves the contents of package.json from the Dependency
            final JsonObject packageJson = jsonReader.readObject();

            // Create a sanitized version of the package.json
            final JsonObject sanitizedJson = SanitizePackage.sanitize(packageJson);

            // Create a new 'package' object that acts as a container for the sanitized package.json
            final JsonObjectBuilder builder = Json.createObjectBuilder();
            final JsonObject nspPayload = builder.add("package", sanitizedJson).build();

            // Submits the package payload to the nsp check service
            final List<Advisory> advisories = searcher.submitPackage(nspPayload);

            for (Advisory advisory : advisories) {
                /*
                 * Create a new vulnerability out of the advisory returned by nsp.
                 */
                final Vulnerability vuln = new Vulnerability();
                vuln.setCvssScore(advisory.getCvssScore());
                vuln.setDescription(advisory.getOverview());
                vuln.setName(String.valueOf(advisory.getId()));
                vuln.setSource(Vulnerability.Source.NSP);
                vuln.addReference(
                        "NSP",
                        "Advisory " + advisory.getId() + ": " + advisory.getTitle(),
                        advisory.getAdvisory()
                );

                /*
                 * Create a single vulnerable software object - these do not use CPEs unlike the NVD.
                 */
                final VulnerableSoftware vs = new VulnerableSoftware();
                //vs.setVersion(advisory.getVulnerableVersions());
                vs.setUpdate(advisory.getPatchedVersions());
                vs.setName(advisory.getModule() + ":" + advisory.getVulnerableVersions());
                vuln.setVulnerableSoftware(new HashSet<>(Arrays.asList(vs)));

                // Add the vulnerability to package.json
                dependency.getVulnerabilities().add(vuln);
            }

            /*
             * Adds evidence about the node package itself, not any of the modules.
             */
            final EvidenceCollection productEvidence = dependency.getProductEvidence();
            final EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
            if (packageJson.containsKey("name")) {
                final Object value = packageJson.get("name");
                if (value instanceof JsonString) {
                    final String valueString = ((JsonString) value).getString();
                    productEvidence.addEvidence(PACKAGE_JSON, "name", valueString, Confidence.HIGHEST);
                    vendorEvidence.addEvidence(PACKAGE_JSON, "name_project", String.format("%s_project", valueString), Confidence.LOW);
                } else {
                    LOGGER.warn("JSON value not string as expected: {}", value);
                }
            }

            /*
             * Processes the dependencies objects in package.json and adds all the modules as related dependencies
             */
            if (packageJson.containsKey("dependencies")) {
                final JsonObject dependencies = packageJson.getJsonObject("dependencies");
                processPackage(dependency, dependencies, "dependencies");
            }
            if (packageJson.containsKey("devDependencies")) {
                final JsonObject dependencies = packageJson.getJsonObject("devDependencies");
                processPackage(dependency, dependencies, "devDependencies");
            }
            if (packageJson.containsKey("optionalDependencies")) {
                final JsonObject dependencies = packageJson.getJsonObject("optionalDependencies");
                processPackage(dependency, dependencies, "optionalDependencies");
            }
            if (packageJson.containsKey("peerDependencies")) {
                final JsonObject dependencies = packageJson.getJsonObject("peerDependencies");
                processPackage(dependency, dependencies, "peerDependencies");
            }
            if (packageJson.containsKey("bundleDependencies")) {
                final JsonArray dependencies = packageJson.getJsonArray("bundleDependencies");
                processPackage(dependency, dependencies, "bundleDependencies");
            }
            if (packageJson.containsKey("bundledDependencies")) {
                final JsonArray dependencies = packageJson.getJsonArray("bundledDependencies");
                processPackage(dependency, dependencies, "bundledDependencies");
            }

            /*
             * Adds the license if defined in package.json
             */
            if (packageJson.containsKey("license")) {
                final Object value = packageJson.get("license");
                if (value instanceof JsonString) {
                    dependency.setLicense(packageJson.getString("license"));
                } else {
                    dependency.setLicense(packageJson.getJsonObject("license").getString("type"));
                }
            }

            /*
             * Adds general evidence to about the package.
             */
            addToEvidence(packageJson, productEvidence, "description");
            addToEvidence(packageJson, vendorEvidence, "author");
            addToEvidence(packageJson, dependency.getVersionEvidence(), "version");
            dependency.setDisplayFileName(String.format("%s/%s", file.getParentFile().getName(), file.getName()));
        } catch (URLConnectionFailureException e) {
            this.setEnabled(false);
            throw new AnalysisException(e.getMessage(), e);
        } catch (IOException e) {
            LOGGER.debug("Error reading dependency or connecting to Node Security Platform - check API", e);
            this.setEnabled(false);
            throw new AnalysisException(e.getMessage(), e);
        } catch (JsonException e) {
            throw new AnalysisException(String.format("Failed to parse %s file.", file.getPath()), e);
        }
    }

    /**
     * Processes a part of package.json (as defined by JsonArray) and update
     * the specified dependency with relevant info.
     *
     * @param dependency the Dependency to update
     * @param jsonArray the jsonArray to parse
     * @param depType the dependency type
     */
    private void processPackage(Dependency dependency, JsonArray jsonArray, String depType) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        for (JsonString str : jsonArray.getValuesAs(JsonString.class)) {
            builder.add(str.toString(), "");
        }
        JsonObject jsonObject = builder.build();
        processPackage(dependency, jsonObject, depType);
    }

    /**
     * Processes a part of package.json (as defined by JsonObject) and update
     * the specified dependency with relevant info.
     *
     * @param dependency the Dependency to update
     * @param jsonObject the jsonObject to parse
     * @param depType the dependency type
     */
    private void processPackage(Dependency dependency, JsonObject jsonObject, String depType) {
        for (int i = 0; i < jsonObject.size(); i++) {
            for (Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {
                /*
                 * Create identifies that include the npm module and version. Since these are defined,
                 * assign the highest confidence.
                 */
                final Identifier moduleName = new Identifier("npm", "Module", null, entry.getKey());
                moduleName.setConfidence(Confidence.HIGHEST);
                String version = "";
                if (entry.getValue() != null && entry.getValue().getValueType() == JsonValue.ValueType.STRING) {
                    version = ((JsonString) entry.getValue()).getString();
                }
                final Identifier moduleVersion = new Identifier("npm", "Version", null, version);
                moduleVersion.setConfidence(Confidence.HIGHEST);

                final Identifier moduleDepType = new Identifier("npm", "Scope", null, depType);
                moduleVersion.setConfidence(Confidence.HIGHEST);

                /*
                 * Create related dependencies for each module defined in package.json. The path to the related
                 * dependency will not actually exist but needs to be unique (due to the use of Set in Dependency).
                 * The use of related dependencies is a way to specify the actual software BOM in package.json.
                 */
                final Dependency nodeModule = new Dependency(new File(dependency.getActualFile() + "#" + entry.getKey()), true);
                nodeModule.setDisplayFileName(entry.getKey());
                nodeModule.setIdentifiers(new HashSet<>(Arrays.asList(moduleName, moduleVersion, moduleDepType)));
                dependency.addRelatedDependency(nodeModule);
            }
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
