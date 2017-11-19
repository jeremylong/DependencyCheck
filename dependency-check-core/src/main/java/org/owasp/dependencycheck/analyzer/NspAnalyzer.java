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
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;

/**
 * Used to analyze Node Package Manager (npm) package.json files via Node
 * Security Platform (nsp).
 *
 * @author Steve Springett
 */
@ThreadSafe
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
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "npm";
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
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        LOGGER.debug("Initializing {}", getName());
        try {
            searcher = new NspSearch(getSettings());
        } catch (MalformedURLException ex) {
            setEnabled(false);
            throw new InitializationException("The configured URL to Node Security Platform is malformed", ex);
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
     * Returns the key used in the properties file to determine if the analyzer
     * is enabled.
     *
     * @return the enabled property setting key for the analyzer
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NSP_PACKAGE_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final File file = dependency.getActualFile();
        if (!file.isFile() || file.length() == 0) {
            return;
        }

        try (JsonReader jsonReader = Json.createReader(FileUtils.openInputStream(file))) {

            // Retrieves the contents of package.json from the Dependency
            final JsonObject packageJson = jsonReader.readObject();

            if (dependency.getEcosystem() == null || dependency.getName() == null) {
                NodePackageAnalyzer.gatherEvidence(packageJson, dependency);
                dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
            }

            // Do not scan the node_modules directory
            if (file.getCanonicalPath().contains(File.separator + "node_modules" + File.separator)) {
                LOGGER.debug("Skipping analysis of node module: " + file.getCanonicalPath());
                return;
            }

            //Processes the dependencies objects in package.json and adds all the modules as dependencies
            if (packageJson.containsKey("dependencies")) {
                final JsonObject dependencies = packageJson.getJsonObject("dependencies");
                processPackage(engine, dependency, dependencies, "dependencies");
            }
            if (packageJson.containsKey("devDependencies")) {
                final JsonObject dependencies = packageJson.getJsonObject("devDependencies");
                processPackage(engine, dependency, dependencies, "devDependencies");
            }
            if (packageJson.containsKey("optionalDependencies")) {
                final JsonObject dependencies = packageJson.getJsonObject("optionalDependencies");
                processPackage(engine, dependency, dependencies, "optionalDependencies");
            }
            if (packageJson.containsKey("peerDependencies")) {
                final JsonObject dependencies = packageJson.getJsonObject("peerDependencies");
                processPackage(engine, dependency, dependencies, "peerDependencies");
            }
            if (packageJson.containsKey("bundleDependencies")) {
                final JsonArray dependencies = packageJson.getJsonArray("bundleDependencies");
                processPackage(engine, dependency, dependencies, "bundleDependencies");
            }
            if (packageJson.containsKey("bundledDependencies")) {
                final JsonArray dependencies = packageJson.getJsonArray("bundledDependencies");
                processPackage(engine, dependency, dependencies, "bundledDependencies");
            }

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
                //TODO consider changing this to available versions on the dependency
                //vs.setUpdate(advisory.getPatchedVersions());

                vs.setName(advisory.getModule() + ":" + advisory.getVulnerableVersions());
                vuln.setVulnerableSoftware(new HashSet<>(Arrays.asList(vs)));

                final Dependency existing = findDependency(engine, advisory.getModule(), advisory.getVersion());
                if (existing == null) {
                    final Dependency nodeModule = createDependency(dependency, advisory.getModule(), advisory.getVersion(), "transitive");
                    nodeModule.addVulnerability(vuln);
                    engine.addDependency(nodeModule);
                } else {
                    existing.addVulnerability(vuln);
                }
            }
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
     * Construct a dependency object.
     *
     * @param dependency the parent dependency
     * @param name the name of the dependency to create
     * @param version the version of the dependency to create
     * @param scope the scope of the dependency being created
     * @return the generated dependency
     */
    private Dependency createDependency(Dependency dependency, String name, String version, String scope) {
        final Dependency nodeModule = new Dependency(new File(dependency.getActualFile() + "?" + name), true);
        nodeModule.setEcosystem(DEPENDENCY_ECOSYSTEM);
        //this is virtual - the sha1 is purely for the hyperlink in the final html report
        nodeModule.setSha1sum(Checksum.getSHA1Checksum(String.format("%s:%s", name, version)));
        nodeModule.setMd5sum(Checksum.getMD5Checksum(String.format("%s:%s", name, version)));
        nodeModule.addEvidence(EvidenceType.PRODUCT, "package.json", "name", name, Confidence.HIGHEST);
        nodeModule.addEvidence(EvidenceType.VENDOR, "package.json", "name", name, Confidence.HIGH);
        nodeModule.addEvidence(EvidenceType.VERSION, "package.json", "version", version, Confidence.HIGHEST);
        nodeModule.addProjectReference(dependency.getName() + ": " + scope);
        nodeModule.setName(name);
        nodeModule.setVersion(version);
        nodeModule.addIdentifier("npm", String.format("%s:%s", name, version), null, Confidence.HIGHEST);
        return nodeModule;
    }

    /**
     * Processes a part of package.json (as defined by JsonArray) and update the
     * specified dependency with relevant info.
     *
     * @param engine the dependency-check engine
     * @param dependency the Dependency to update
     * @param jsonArray the jsonArray to parse
     * @param depType the dependency type
     */
    private void processPackage(Engine engine, Dependency dependency, JsonArray jsonArray, String depType) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        for (JsonString str : jsonArray.getValuesAs(JsonString.class)) {
            builder.add(str.toString(), "");
        }
        final JsonObject jsonObject = builder.build();
        processPackage(engine, dependency, jsonObject, depType);
    }

    /**
     * Processes a part of package.json (as defined by JsonObject) and update
     * the specified dependency with relevant info.
     *
     * @param engine the dependency-check engine
     * @param dependency the Dependency to update
     * @param jsonObject the jsonObject to parse
     * @param depType the dependency type
     */
    private void processPackage(Engine engine, Dependency dependency, JsonObject jsonObject, String depType) {
        for (int i = 0; i < jsonObject.size(); i++) {
            for (Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {

                final String name = entry.getKey();
                String version = "";
                if (entry.getValue() != null && entry.getValue().getValueType() == JsonValue.ValueType.STRING) {
                    version = ((JsonString) entry.getValue()).getString();
                }
                final Dependency existing = findDependency(engine, name, version);
                if (existing == null) {
                    final Dependency nodeModule = createDependency(dependency, name, version, depType);
                    engine.addDependency(nodeModule);
                } else {
                    existing.addProjectReference(dependency.getName() + ": " + depType);
                }
            }
        }
    }

    /**
     * Adds information to an evidence collection from the node json
     * configuration.
     *
     * @param dep the dependency to which the evidence will be added
     * @param type the type of evidence to be added
     * @param json information from node.js
     * @param key the key to obtain the data from the json information
     */
    private void addToEvidence(Dependency dep, EvidenceType type, JsonObject json, String key) {
        if (json.containsKey(key)) {
            final JsonValue value = json.get(key);
            if (value instanceof JsonString) {
                dep.addEvidence(type, PACKAGE_JSON, key, ((JsonString) value).getString(), Confidence.HIGHEST);
            } else if (value instanceof JsonObject) {
                final JsonObject jsonObject = (JsonObject) value;
                for (final Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {
                    final String property = entry.getKey();
                    final JsonValue subValue = entry.getValue();
                    if (subValue instanceof JsonString) {
                        dep.addEvidence(type, PACKAGE_JSON,
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

    /**
     * Locates the dependency from the list of dependencies that have been
     * scanned by the engine.
     *
     * @param engine the dependency-check engine
     * @param name the name of the dependency to find
     * @param version the version of the dependency to find
     * @return the identified dependency; otherwise null
     */
    private Dependency findDependency(Engine engine, String name, String version) {
        for (Dependency d : engine.getDependencies()) {
            if (DEPENDENCY_ECOSYSTEM.equals(d.getEcosystem()) && name.equals(d.getName()) && version != null && d.getVersion() != null) {
                String dependencyVersion = d.getVersion();
                if (dependencyVersion.startsWith("^") || dependencyVersion.startsWith("~")) {
                    dependencyVersion = dependencyVersion.substring(1);
                }

                if (version.equals(dependencyVersion)) {
                    return d;
                }
                if (version.startsWith("^") || version.startsWith("~") || version.contains("*")) {
                    String type;
                    String tmp;
                    if (version.startsWith("^") || version.startsWith("~")) {
                        type = version.substring(0, 1);
                        tmp = version.substring(1);
                    } else {
                        type = "*";
                        tmp = version;
                    }
                    final String[] v = tmp.split(" ")[0].split("\\.");
                    final String[] depVersion = dependencyVersion.split("\\.");

                    if ("^".equals(type) && v[0].equals(depVersion[0])) {
                        return d;
                    } else if ("~".equals(type) && v.length >= 2 && depVersion.length >= 2
                            && v[0].equals(depVersion[0]) && v[1].equals(depVersion[1])) {
                        return d;
                    } else if (v[0].equals("*")
                            || (v.length >= 2 && v[0].equals(depVersion[0]) && v[1].equals("*"))
                            || (v.length >= 3 && depVersion.length >= 2 && v[0].equals(depVersion[0])
                            && v[1].equals(depVersion[1]) && v[2].equals("*"))) {
                        return d;
                    }
                }
            }
        }
        return null;
    }
}
