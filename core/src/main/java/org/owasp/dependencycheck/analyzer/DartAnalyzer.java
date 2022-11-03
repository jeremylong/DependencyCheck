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
 * Copyright (c) 2022 Marc Rödder. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

/**
 * This analyzer is used to analyze Dart packages by collecting information from
 * pubspec lock and yaml files. See https://dart.dev/tools/pub/pubspec
 *
 * @author Marc Rödder (http://github.com/sticksen)
 */
@Experimental
@ThreadSafe
public class DartAnalyzer extends AbstractFileTypeAnalyzer {

//    /**
//     * A descriptor for the type of dependencies processed or added by this
//     * analyzer.
//     */
//    // currently not supported by Sonatype OSS
//    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.DART;
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DartAnalyzer.class);

    /**
     * The lock file name.
     */
    private static final String LOCK_FILE = "pubspec.lock";
    /**
     * The YAML file name.
     */
    private static final String YAML_FILE = "pubspec.yaml";

    @Override
    protected FileFilter getFileFilter() {
        return FileFilterBuilder.newInstance().addFilenames(LOCK_FILE, YAML_FILE).build();
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) {
        // NO-OP
    }

    @Override
    public String getName() {
        return "Dart Package Analyzer";
    }

    /**
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_DART_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine)
            throws AnalysisException {
        final String fileName = dependency.getFileName();
        LOGGER.debug("Checking file {}", fileName);

        switch (fileName) {
            case LOCK_FILE:
                analyzeLockFileDependencies(dependency, engine);
                break;
            case YAML_FILE:
                analyzeYamlFileDependencies(dependency, engine);
                break;
            default:
            //do nothing
        }
    }

    private void analyzeYamlFileDependencies(Dependency yamlFileDependency, Engine engine) throws AnalysisException {
        engine.removeDependency(yamlFileDependency);
        final File yamlFile = yamlFileDependency.getActualFile();
        if (YAML_FILE.equals(yamlFile.getName())) {
            final File lock = new File(yamlFile.getParentFile(), LOCK_FILE);
            if (lock.isFile()) {
                LOGGER.debug("Skipping {} because {} exists", yamlFile, lock);
                return;
            }
        }

        final JsonNode rootNode;
        final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
        try {
            rootNode = objectMapper.readTree(yamlFile);
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }

        if (rootNode.hasNonNull("dependencies")) {
            final Iterator<Map.Entry<String, JsonNode>> dependencies = rootNode.get("dependencies").fields();
            addYamlDependenciesToEngine(dependencies, yamlFile, engine);
        }
        //TODO - add configuration to allow skipping dev dependencies.
        if (rootNode.hasNonNull("dev_dependencies")) {
            final Iterator<Map.Entry<String, JsonNode>> devDependencies = rootNode.get("dev_dependencies").fields();
            addYamlDependenciesToEngine(devDependencies, yamlFile, engine);
        }

        addYamlDartDependencyToEngine(rootNode, yamlFile, engine);
    }

    private void analyzeLockFileDependencies(Dependency lockFileDependency, Engine engine) throws AnalysisException {
        engine.removeDependency(lockFileDependency);

        final JsonNode rootNode;
        final File lockFile = lockFileDependency.getActualFile();
        final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
        try {
            rootNode = objectMapper.readTree(lockFile);
        } catch (IOException e) {
            throw new AnalysisException("Problem occurred while reading dependency lockFile.", e);
        }

        addLockFileDependenciesToEngine(lockFile, engine, rootNode);
        addLockFileDartVersionToEngine(lockFile, engine, rootNode);
    }

    private void addLockFileDartVersionToEngine(File file, Engine engine, JsonNode rootNode) throws AnalysisException {
        final String dartVersion = rootNode.get("sdks").get("dart").textValue();
        final String minimumVersion = extractMinimumVersion(dartVersion);

        engine.addDependency(
                createDependencyFromNameAndVersion(file, "dart_software_development_kit", minimumVersion));
    }

    private void addLockFileDependenciesToEngine(File file, Engine engine, JsonNode rootNode) throws AnalysisException {
        for (JsonNode nextPackage : rootNode.get("packages")) {
            final JsonNode description = nextPackage.get("description");
            if (description == null) {
                continue;
            }

            final JsonNode nameNode = description.get("name");
            if (nameNode == null) {
                continue;
            }

            final JsonNode versionNode = nextPackage.get("version");
            if (versionNode == null) {
                continue;
            }

            final String name = nameNode.asText();
            final String version = versionNode.asText();
            LOGGER.debug("Found dependency in {} file, name: {}, version: {}", LOCK_FILE, name, version);

            engine.addDependency(
                    createDependencyFromNameAndVersion(file, name, version)
            );
        }
    }

    private void addYamlDependenciesToEngine(Iterator<Map.Entry<String, JsonNode>> dependencies, File file, Engine engine) throws AnalysisException {
        while (dependencies.hasNext()) {
            final Map.Entry<String, JsonNode> entry = dependencies.next();

            final String name = entry.getKey();
            final String versionRaw = entry.getValue().asText();
            final String version = extractMinimumVersion(versionRaw);
            LOGGER.debug("Found dependency in {} file, name: {}, version: {}", YAML_FILE, name, version);

            engine.addDependency(
                    createDependencyFromNameAndVersion(file, name, version)
            );
        }
    }

    private void addYamlDartDependencyToEngine(JsonNode rootNode, File file, Engine engine) throws AnalysisException {
        if (rootNode.hasNonNull("environment") && rootNode.get("environment").hasNonNull("sdk")) {
            final String dartVersion = rootNode.get("environment").get("sdk").textValue();
            final String minimumVersion = extractMinimumVersion(dartVersion);

            engine.addDependency(
                    createDependencyFromNameAndVersion(file, "dart_software_development_kit", minimumVersion));
        }
    }

    private Dependency createDependencyFromNameAndVersion(File file, String name, String version) throws AnalysisException {
        final Dependency dependency = new Dependency(file, true);

        // currently not supported by Sonatype OSS
//            // dependency.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dependency.setName(name);
        dependency.setVersion(version);

        final PackageURL packageURL;
        try {
            packageURL = PackageURLBuilder
                    .aPackageURL()
                    .withType("pub")
                    .withName(dependency.getName())
                    .withVersion(version.isEmpty() ? null : version)
                    .build();

        } catch (MalformedPackageURLException e) {
            throw new AnalysisException("Problem occurred while reading dependency file.", e);
        }

        dependency.addSoftwareIdentifier(new PurlIdentifier(packageURL, Confidence.HIGHEST));

        dependency.addEvidence(EvidenceType.PRODUCT, file.getName(), "name", name, Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VENDOR, file.getName(), "name", name, Confidence.HIGHEST);
        dependency.addEvidence(EvidenceType.VENDOR, file.getName(), "name", "dart", Confidence.HIGHEST);
        if (!version.isEmpty()) {
            dependency.addEvidence(EvidenceType.VERSION, file.getName(), "version", version, Confidence.MEDIUM);
        }

        final String packagePath = String.format("%s:%s", name, version);
        dependency.setSha1sum(Checksum.getSHA1Checksum(packagePath));
        dependency.setSha256sum(Checksum.getSHA256Checksum(packagePath));
        dependency.setMd5sum(Checksum.getMD5Checksum(packagePath));
        dependency.setPackagePath(packagePath);
        dependency.setDisplayFileName(packagePath);

        return dependency;
    }

    private String extractMinimumVersion(String versionRaw) {
        final String version;
        if (versionRaw.contains("^")) {
            version = versionRaw.replace("^", "");
        } else if (versionRaw.contains("<")) {
            // this code should parse version definitions like ">=2.10.0 <3.0.0"
            final String firstPart = versionRaw.split("<")[0].trim();
            version = firstPart.replace(">=", "").trim();
        } else if (versionRaw.contains("any") || versionRaw.equals("null")) {
            version = "";
        } else {
            version = versionRaw;
        }

        LOGGER.debug("Extracted minimum version: {} from raw version: {}", version, versionRaw);
        return version;
    }
}
