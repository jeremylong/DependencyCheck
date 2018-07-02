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

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.Checksum;

/**
 * An abstract NPM analyzer that contains common methods for concrete
 * implementations.
 *
 * @author Steve Springett
 */
@ThreadSafe
public abstract class AbstractNpmAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractNpmAnalyzer.class);

    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String NPM_DEPENDENCY_ECOSYSTEM = "npm";
    /**
     * The file name to scan.
     */
    private static final String PACKAGE_JSON = "package.json";

    /**
     * Determines if the file can be analyzed by the analyzer.
     *
     * @param pathname the path to the file
     * @return true if the file can be analyzed by the given analyzer; otherwise
     * false
     */
    @Override
    public boolean accept(File pathname) {
        boolean accept = super.accept(pathname);
        if (accept) {
            try {
                accept |= shouldProcess(pathname);
            } catch (AnalysisException ex) {
                throw new RuntimeException(ex.getMessage(), ex.getCause());
            }
        }

        return accept;
    }

    /**
     * Determines if the path contains "/node_modules/" (i.e. it is a child
     * module. This analyzer does not scan child modules.
     *
     * @param pathname the path to test
     * @return <code>true</code> if the path does not contain "/node_modules/"
     * @throws AnalysisException thrown if the canonical path cannot be obtained
     * from the given file
     */
    protected boolean shouldProcess(File pathname) throws AnalysisException {
        try {
            // Do not scan the node_modules directory
            if (pathname.getCanonicalPath().contains(File.separator + "node_modules" + File.separator)) {
                LOGGER.debug("Skipping analysis of node module: " + pathname.getCanonicalPath());
                return false;
            }
        } catch (IOException ex) {
            throw new AnalysisException("Unable to process dependency", ex);
        }
        return true;
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
    protected Dependency createDependency(Dependency dependency, String name, String version, String scope) {
        final Dependency nodeModule = new Dependency(new File(dependency.getActualFile() + "?" + name), true);
        nodeModule.setEcosystem(NPM_DEPENDENCY_ECOSYSTEM);
        //this is virtual - the sha1 is purely for the hyperlink in the final html report
        nodeModule.setSha1sum(Checksum.getSHA1Checksum(String.format("%s:%s", name, version)));
        nodeModule.setSha256sum(Checksum.getSHA256Checksum(String.format("%s:%s", name, version)));
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
    protected void processPackage(Engine engine, Dependency dependency, JsonArray jsonArray, String depType) {
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
    protected void processPackage(Engine engine, Dependency dependency, JsonObject jsonObject, String depType) {
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

    /**
     * Locates the dependency from the list of dependencies that have been
     * scanned by the engine.
     *
     * @param engine the dependency-check engine
     * @param name the name of the dependency to find
     * @param version the version of the dependency to find
     * @return the identified dependency; otherwise null
     */
    protected Dependency findDependency(Engine engine, String name, String version) {
        for (Dependency d : engine.getDependencies()) {
            if (NPM_DEPENDENCY_ECOSYSTEM.equals(d.getEcosystem()) && name.equals(d.getName()) && version != null && d.getVersion() != null) {
                final String dependencyVersion = d.getVersion();
                if (DependencyBundlingAnalyzer.npmVersionsMatch(version, dependencyVersion)) {
                    return d;
                }
            }
        }
        return null;
    }

    /**
     * Collects evidence from the given JSON for the associated dependency.
     *
     * @param json the JSON that contains the evidence to collect
     * @param dependency the dependency to add the evidence too
     */
    public void gatherEvidence(final JsonObject json, Dependency dependency) {
        String displayName = null;
        if (json.containsKey("name")) {
            final Object value = json.get("name");
            if (value instanceof JsonString) {
                final String valueString = ((JsonString) value).getString();
                displayName = valueString;
                dependency.setName(valueString);
                dependency.setPackagePath(valueString);
                dependency.addEvidence(EvidenceType.PRODUCT, PACKAGE_JSON, "name", valueString, Confidence.HIGHEST);
                dependency.addEvidence(EvidenceType.VENDOR, PACKAGE_JSON, "name", valueString, Confidence.HIGH);
            } else {
                LOGGER.warn("JSON value not string as expected: {}", value);
            }
        }
        final String desc = addToEvidence(dependency, EvidenceType.PRODUCT, json, "description");
        dependency.setDescription(desc);
        final String vendor = addToEvidence(dependency, EvidenceType.VENDOR, json, "author");
        final String version = addToEvidence(dependency, EvidenceType.VERSION, json, "version");
        if (version != null) {
            displayName = String.format("%s:%s", displayName, version);
            dependency.setVersion(version);
            dependency.addIdentifier("npm", String.format("%s:%s", dependency.getName(), version), null, Confidence.HIGHEST);
        }
        if (displayName != null) {
            dependency.setDisplayFileName(displayName);
            dependency.setPackagePath(displayName);
        } else {
            LOGGER.warn("Unable to determine package name or version for {}", dependency.getActualFilePath());
            if (vendor != null && !vendor.isEmpty()) {
                dependency.setDisplayFileName(String.format("%s package.json", vendor));
            }
        }
        // Adds the license if defined in package.json
        if (json.containsKey("license")) {
            final Object value = json.get("license");
            if (value instanceof JsonString) {
                dependency.setLicense(json.getString("license"));
            } else if (value instanceof JsonArray) {
                final JsonArray array = (JsonArray) value;
                final StringBuilder sb = new StringBuilder();
                boolean addComma = false;
                for (int x = 0; x < array.size(); x++) {
                    if (!array.isNull(x)) {
                        if (addComma) {
                            sb.append(", ");
                        } else {
                            addComma = true;
                        }
                        sb.append(array.getString(x));
                    }
                }
                dependency.setLicense(sb.toString());
            } else {
                dependency.setLicense(json.getJsonObject("license").getString("type"));
            }
        }
    }
}
