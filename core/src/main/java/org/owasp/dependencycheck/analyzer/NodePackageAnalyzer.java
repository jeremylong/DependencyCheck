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
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import org.owasp.dependencycheck.Engine.Mode;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.InvalidSettingException;

/**
 * Used to analyze Node Package Manager (npm) package.json files, and collect
 * information that can be used to determine the associated CPE.
 *
 * @author Dale Visser
 */
@ThreadSafe
public class NodePackageAnalyzer extends AbstractNpmAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NodePackageAnalyzer.class);
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = NPM_DEPENDENCY_ECOSYSTEM;
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
     * The file name to scan.
     */
    public static final String PACKAGE_LOCK_JSON = "package-lock.json";
    /**
     * The file name to scan.
     */
    public static final String SHRINKWRAP_JSON = "npm-shrinkwrap.json";
    /**
     * Filter that detects files named "package-lock.json" or
     * "npm-shrinkwrap.json".
     */
    private static final FileFilter PACKAGE_JSON_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(PACKAGE_LOCK_JSON, SHRINKWRAP_JSON).build();

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
                final String[] tmp = settings.getArray(Settings.KEYS.ECOSYSTEM_SKIP_CPEANALYZER);
                if (tmp != null) {
                    final List<String> skipEcosystems = Arrays.asList(tmp);
                    if (skipEcosystems.contains(DEPENDENCY_ECOSYSTEM)
                            && !settings.getBoolean(Settings.KEYS.ANALYZER_NSP_PACKAGE_ENABLED)) {
                        LOGGER.debug("NodePackageAnalyzer enabled without a corresponding vulnerability analyzer");
                        final String msg = "Invalid Configuration: enabling the Node Package Analyzer without "
                                + "using the NSP Analyzer is not supported.";
                        throw new InitializationException(msg);
                    } else if (!skipEcosystems.contains(DEPENDENCY_ECOSYSTEM)) {
                        LOGGER.warn("Using the CPE Analyzer with Node.js can result in many false positives.");
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
     * Returns the key used in the properties file to reference the enabled
     * property for the analyzer.
     *
     * @return the enabled property setting key for the analyzer
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (!PACKAGE_JSON.equals(dependency.getFileName())) {
            engine.removeDependency(dependency);
        }
        final File dependencyFile = dependency.getActualFile();
        if (!dependencyFile.isFile() || dependencyFile.length() == 0 || !shouldProcess(dependencyFile)) {
            return;
        }
        final File baseDir = dependencyFile.getParentFile();
        if (PACKAGE_LOCK_JSON.equals(dependency.getFileName())) {
            final File shrinkwrap = new File(baseDir, SHRINKWRAP_JSON);
            if (shrinkwrap.exists()) {
                return;
            }
        }
        final File nodeModules = new File(baseDir, "node_modules");
        if (!nodeModules.isDirectory()) {
            LOGGER.warn("Analyzing `{}` - however, the node_modules directory does not exist. "
                    + "Please run `npm install` prior to running dependency-check", dependencyFile.toString());
            return;
        }

        try (JsonReader jsonReader = Json.createReader(FileUtils.openInputStream(dependencyFile))) {
            final JsonObject json = jsonReader.readObject();
            final String parentName = json.getString("name", "");
            final String parentVersion = json.getString("version", "");
            if (parentName.isEmpty()) {
                return;
            }
            final String parentPackage;
            if (!parentVersion.isEmpty()) {
                parentPackage = String.format("%s:%s", parentName, parentVersion);
            } else {
                parentPackage = parentName;
            }
            processDependencies(json, baseDir, dependencyFile, parentPackage, engine);
        } catch (JsonException e) {
            LOGGER.warn("Failed to parse package.json file.", e);
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }
    }

    /**
     * Process the dependencies in the lock file by first parsing its
     * dependencies and then finding the package.json for the module and adding
     * it as a dependency.
     *
     * @param json the data to process
     * @param baseDir the base directory being scanned
     * @param rootFile the root package-lock/npm-shrinkwrap being analyzed
     * @param parentPackage the parent package name of the current node
     * @param engine a reference to the dependency-check engine
     * @throws AnalysisException thrown if there is an exception
     */
    private void processDependencies(JsonObject json, File baseDir, File rootFile,
            String parentPackage, Engine engine) throws AnalysisException {
        if (json.containsKey("dependencies")) {
            final JsonObject deps = json.getJsonObject("dependencies");
            for (Map.Entry<String, JsonValue> entry : deps.entrySet()) {
                final JsonObject jo = (JsonObject) entry.getValue();
                final String name = entry.getKey();
                final String version = jo.getString("version");
                final File base = Paths.get(baseDir.getPath(), "node_modules", name).toFile();
                final File f = new File(base, PACKAGE_JSON);

                if (jo.containsKey("dependencies")) {
                    final String subPackageName = String.format("%s/%s:%s", parentPackage, name, version);
                    processDependencies(jo, base, rootFile, subPackageName, engine);
                }

                final Dependency child;
                if (f.exists()) {
                    //TOOD - we should use the integrity value instead of calculating the SHA1/MD5
                    child = new Dependency(f);
                    child.setEcosystem(DEPENDENCY_ECOSYSTEM);

                    try (JsonReader jr = Json.createReader(FileUtils.openInputStream(f))) {
                        final JsonObject childJson = jr.readObject();
                        gatherEvidence(childJson, child);

                    } catch (JsonException e) {
                        LOGGER.warn("Failed to parse package.json file from dependency.", e);
                    } catch (IOException e) {
                        throw new AnalysisException("Problem occurred while reading dependency file.", e);
                    }
                } else {
                    LOGGER.warn("Unable to find node module: {}", f.toString());
                    child = new Dependency(rootFile, true);
                    child.setEcosystem(DEPENDENCY_ECOSYSTEM);
                    //TOOD - we should use the integrity value instead of calculating the SHA1/MD5
                    child.setSha1sum(Checksum.getSHA1Checksum(String.format("%s:%s", name, version)));
                    child.setSha256sum(Checksum.getSHA256Checksum(String.format("%s:%s", name, version)));
                    child.setMd5sum(Checksum.getMD5Checksum(String.format("%s:%s", name, version)));
                    child.addEvidence(EvidenceType.VENDOR, rootFile.getName(), "name", name, Confidence.HIGHEST);
                    child.addEvidence(EvidenceType.PRODUCT, rootFile.getName(), "name", name, Confidence.HIGHEST);
                    child.addEvidence(EvidenceType.VERSION, rootFile.getName(), "version", version, Confidence.HIGHEST);
                    child.setName(name);
                    child.setVersion(version);
                    final String packagePath = String.format("%s:%s", name, version);
                    child.setDisplayFileName(packagePath);
                    child.setPackagePath(packagePath);
                }

                child.addProjectReference(parentPackage);
                child.setEcosystem(DEPENDENCY_ECOSYSTEM);

                final Dependency existing = findDependency(engine, name, version);
                if (existing != null) {
                    if (existing.isVirtual()) {
                        DependencyMergingAnalyzer.mergeDependencies(child, existing, null);
                        engine.removeDependency(existing);
                        engine.addDependency(child);
                    } else {
                        DependencyBundlingAnalyzer.mergeDependencies(existing, child, null);
                    }
                } else {
                    engine.addDependency(child);
                }
            }
        }
    }
}
