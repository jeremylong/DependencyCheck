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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
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
import javax.json.JsonString;
import javax.json.JsonReader;
import javax.json.JsonValue;
import org.owasp.dependencycheck.Engine.Mode;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
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
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.NODEJS;
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
     * Filter that detects files named "package.json", "package-lock.json", or
     * "npm-shrinkwrap.json".
     */
    private static final FileFilter PACKAGE_JSON_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(PACKAGE_JSON, PACKAGE_LOCK_JSON, SHRINKWRAP_JSON).build();

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
                            && !settings.getBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED)) {
                        if (!settings.getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED)) {
                            final String msg = "Invalid Configuration: enabling the Node Package Analyzer without "
                                    + "using the Node Audit Analyzer or OSS Index Analyzer is not supported.";
                            throw new InitializationException(msg);
                        } else if (!isNodeAuditEnabled(engine)) {
                            final String msg = "Missing package.lock or npm-shrinkwrap.lock file: Unable to scan a node "
                                    + "project without a package-lock.json or npm-shrinkwrap.json.";
                            throw new InitializationException(msg);
                        }
                    } else if (skipEcosystems.contains(DEPENDENCY_ECOSYSTEM)
                            && !settings.getBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED)) {
                        LOGGER.warn("Using only the OSS Index Analyzer with Node.js can result in many false positives "
                                + "- please enable the Node Audit Analyzer.");
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

    /**
     * Determines if the Node Audit analyzer is enabled.
     *
     * @param engine a reference to the dependency-check engine
     * @return <code>true</code> if the Node Audit Analyzer is enabled;
     * otherwise <code>false</code>
     */
    private boolean isNodeAuditEnabled(Engine engine) {
        for (Analyzer a : engine.getAnalyzers()) {
            if (a instanceof NodeAuditAnalyzer || a instanceof YarnAuditAnalyzer || a instanceof PnpmAuditAnalyzer) {
                if (a.isEnabled()) {
                    try {
                        ((AbstractNpmAnalyzer) a).prepareFileTypeAnalyzer(engine);
                    } catch (InitializationException ex) {
                        LOGGER.debug("Error initializing the {}", a.getName());
                    }
                }
                return a.isEnabled();
            }
        }
        return false;
    }

    /**
     * Checks if a package lock file or equivalent exists for the NPM project.
     *
     * @param dependencyFile a reference to the `package.json` file
     * @return <code>true</code> if no lock file is found; otherwise
     * <code>true</code>
     */
    private boolean noLockFileExists(File dependencyFile) {
        final File lock = new File(dependencyFile.getParentFile(), "package-lock.json");
        final File shrinkwrap = new File(dependencyFile.getParentFile(), "npm-shrinkwrap.json");
        final File yarnLock = new File(dependencyFile.getParentFile(), "yarn.lock");
        return !(lock.isFile() || shrinkwrap.isFile() || yarnLock.isFile());
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (isNodeAuditEnabled(engine)
                && !(PACKAGE_LOCK_JSON.equals(dependency.getFileName()) || SHRINKWRAP_JSON.equals(dependency.getFileName()))) {
            engine.removeDependency(dependency);
        }
        final File dependencyFile = dependency.getActualFile();
        if (!dependencyFile.isFile() || dependencyFile.length() == 0 || !shouldProcess(dependencyFile)) {
            return;
        }
        if (noLockFileExists(dependency.getActualFile())) {
            LOGGER.warn("No lock file exists - this will result in false negatives; please run `npm install --package-lock`");
        }
        final File baseDir = dependencyFile.getParentFile();
        if (PACKAGE_JSON.equals(dependency.getFileName())) {
            final File lockfile = new File(baseDir, PACKAGE_LOCK_JSON);
            final File shrinkwrap = new File(baseDir, SHRINKWRAP_JSON);
            if (shrinkwrap.exists() || lockfile.exists()) {
                return;
            }
        } else if (PACKAGE_LOCK_JSON.equals(dependency.getFileName())) {
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
            dependency.setName(parentName);
            final String parentPackage;
            if (!parentVersion.isEmpty()) {
                dependency.setVersion(parentVersion);
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
     * should process the dependency ? Will return true if you need to skip it .
     * (e.g. dependency can't be read, or if npm audit doesn't handle it)
     *
     * @param name the name of the dependency
     * @param version the version of the dependency
     * @param optional is the dependency optional ?
     * @param fileExist is the package.json available for this file ?
     * @return should you skip this dependency ?
     */
    public static boolean shouldSkipDependency(String name, String version, boolean optional, boolean fileExist) {
        // some package manager can handle alias, yarn for example, but npm doesn't support it
        if (version.startsWith("npm:")) {
            //TODO make this an error that gets logged
            LOGGER.warn("dependency skipped: package.json contain an alias for {} => {} npm audit doesn't "
                    + "support aliases", name, version.replace("npm:", ""));
            return true;
        }

        if (optional && !fileExist) {
            LOGGER.warn("dependency skipped: node module {} seems optional and not installed", name);
            return true;
        }

        // this seems to produce crash sometimes, I need to tests
        // using a local node_module is not supported by npm audit, it crash
        if (version.startsWith("file:")) {
            LOGGER.warn("dependency skipped: package.json contain an local node_module for {} seems to be "
                    + "located {} npm audit doesn't support locally referenced modules",
                    name, version.replace("file:", ""));
            return true;
        }
        return false;
    }

    /**
     * Checks if the given dependency should be skipped.
     *
     * @see NodePackageAnalyzer#shouldSkipDependency(java.lang.String,
     * java.lang.String, boolean, boolean)
     * @param name the name of the dependency to test
     * @param version the version of the dependency to test
     * @return <code>true</code> if the dependency should be skipped; otherwise
     * <code>false</code>
     */
    public static boolean shouldSkipDependency(String name, String version) {
        return shouldSkipDependency(name, version, false, true);
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
            final boolean skipDev = getSettings().getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_SKIPDEV, false);
            for (Map.Entry<String, JsonValue> entry : deps.entrySet()) {
                final String name = entry.getKey();
                final String version;
                boolean optional = false;
                boolean isDev = false;

                final File base = Paths.get(baseDir.getPath(), "node_modules", name).toFile();
                final File f = new File(base, PACKAGE_JSON);
                JsonObject jo = null;

                if (entry.getValue() instanceof JsonObject) {
                    jo = (JsonObject) entry.getValue();
                    version = jo.getString("version");
                    optional = jo.getBoolean("optional", false);
                    isDev = jo.getBoolean("dev", false);
                } else {
                    version = ((JsonString) entry.getValue()).getString();
                }

                if ((isDev && skipDev) || shouldSkipDependency(name, version, optional, f.exists())) {
                    continue;
                }

                if (null != jo && jo.containsKey("dependencies")) {
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
                    try {
                        final PackageURL purl = PackageURLBuilder.aPackageURL().withType("npm").withName(name).withVersion(version).build();
                        final PurlIdentifier id = new PurlIdentifier(purl, Confidence.HIGHEST);
                        child.addSoftwareIdentifier(id);
                    } catch (MalformedPackageURLException ex) {
                        LOGGER.debug("Unable to build package url for `" + packagePath + "`", ex);
                    }
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
