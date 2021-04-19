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
 * Copyright (c) 2019 Matthijs van den Bos. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.golang;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURLBuilder;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.owasp.dependencycheck.analyzer.GolangModAnalyzer.DEPENDENCY_ECOSYSTEM;
import static org.owasp.dependencycheck.analyzer.GolangModAnalyzer.GO_MOD;
import org.owasp.dependencycheck.utils.Checksum;

/**
 * Represents a Go module dependency.
 *
 * @author Matthijs van den Bos
 */
public class GoModDependency {

    /**
     * A reference to the logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GoModDependency.class);
    /**
     * A list of license files we recognize.
     */
    private static final Set<String> LICENSE_FILES = new HashSet<String>(Arrays.asList("LICENSE", "LICENCE", "LICENSE.TXT",
            "LICENSE.MD", "LICENCE.MD", "LICENSE.CODE", "LICENCE.CODE", "COPYING"));
    /**
     * The module path.
     */
    private final String modulePath;
    /**
     * The version.
     */
    private final String version;
    /**
     * A Package-URL builder.
     */
    private final PackageURLBuilder packageURLBuilder;
    /**
     * The module Dir.
     */
    private final String dir;

    /**
     * Constructs a new GoModDependency.
     *
     * @param modulePath the module path
     * @param version the dependency version
     * @param dir the directory that the module exists within
     */
    GoModDependency(String modulePath, String version, String dir) {
        this.modulePath = modulePath;
        this.version = version;
        this.dir = dir;
        packageURLBuilder = PackageURLBuilder.aPackageURL().withType("golang");
    }

    /**
     * Converts the GoModDependency into a Dependency object.
     *
     * @param parentDependency the parent dependency
     * @return the resulting Dependency object
     */
    public Dependency toDependency(Dependency parentDependency) {
        return createDependency(parentDependency, modulePath, version);
    }

    /**
     * Builds a dependency object based on the given data.
     *
     * @param parentDependency a reference to the parent dependency
     * @param name the name of the dependency
     * @param version the version of the dependency
     * @return a new dependency object
     */
    private Dependency createDependency(Dependency parentDependency, String name, String version) {
        final Dependency dep = new Dependency(parentDependency.getActualFile(), true);

        String namespace = null;
        String vendor = null;
        String moduleName = null;
        String packageNamespace = null;

        // separate the product from the vendor
        final int lastSlash = name.lastIndexOf("/");
        if (lastSlash > 0) {
            packageNamespace = name.substring(0, lastSlash);
            final int pos = packageNamespace.indexOf("/");
            if (pos > 0) {
                namespace = packageNamespace.substring(0, pos);
                vendor = packageNamespace.substring(pos + 1);
            }
            moduleName = name.substring(lastSlash + 1);
        } else {
            moduleName = name;
        }

        final String filePath = String.format("%s:%s/%s/%s", parentDependency.getFilePath(), packageNamespace, moduleName, version);
        //virtual dep need a sha1 for the html report
        dep.setSha1sum(Checksum.getSHA1Checksum(filePath));
        packageURLBuilder.withName(moduleName);
        packageURLBuilder.withNamespace(packageNamespace);
        if (StringUtils.isNotBlank(version)) {
            packageURLBuilder.withVersion(version);
        }
        dep.setEcosystem(DEPENDENCY_ECOSYSTEM);
        dep.setDisplayFileName(name + ":" + version);
        dep.setName(moduleName);
        if (StringUtils.isNotBlank(version)) {
            dep.setVersion(version);
            dep.setPackagePath(String.format("%s:%s", name, version));
        }
        dep.setFilePath(filePath);

        if (vendor != null) {
            dep.addEvidence(EvidenceType.VENDOR, GO_MOD, "vendor", vendor, Confidence.HIGHEST);
            dep.addEvidence(EvidenceType.PRODUCT, GO_MOD, "vendor", vendor, Confidence.MEDIUM);
        }
        if (namespace != null && !"golang.org".equals(namespace)) {
            dep.addEvidence(EvidenceType.VENDOR, GO_MOD, "namespace", namespace, Confidence.LOW);
        }
        dep.addEvidence(EvidenceType.PRODUCT, GO_MOD, "name", moduleName, Confidence.HIGHEST);
        dep.addEvidence(EvidenceType.VENDOR, GO_MOD, "name", moduleName, Confidence.HIGH);
        if (StringUtils.isNotBlank(version)) {
            dep.addEvidence(EvidenceType.VERSION, GO_MOD, "version", version, Confidence.HIGHEST);
        }
        Identifier id;
        try {
            id = new PurlIdentifier(packageURLBuilder.build(), Confidence.HIGHEST);
        } catch (MalformedPackageURLException ex) {
            LOGGER.warn("Unable to create package-url identifier for `{}` in `{}` - reason: {}",
                    name, parentDependency.getFilePath(), ex.getMessage());
            final StringBuilder value = new StringBuilder(name);
            if (StringUtils.isNotBlank(version)) {
                value.append("@").append(version);
            }
            id = new GenericIdentifier(value.toString(), Confidence.HIGH);
        }
        dep.addSoftwareIdentifier(id);
        if (StringUtils.isNotBlank(dir)) {
            final File file = new File(dir);
            if (file.exists()) {
                dep.setFilePath(file.getAbsolutePath());
                dep.setActualFilePath(file.getAbsolutePath());
                dep.setFileName(file.getName());
                extractLicense(dep, file);
            }
        }
        return dep;
    }

    /**
     * Extracts the content of the license file into the dependency's license
     * field.
     *
     *
     * @param dependency the dependency being analyzed
     * @param file the license file
     */
    private void extractLicense(Dependency dependency, File file) {
        final File[] files = file.listFiles();
        if (files != null) {
            for (File f : files) {
                if (LICENSE_FILES.contains(f.getName().toUpperCase())) {
                    try {
                        final String license = FileUtils.readFileToString(f, Charset.forName("UTF-8"));
                        dependency.setLicense(license);
                        break;
                    } catch (IOException ex) {
                        LOGGER.debug("Error reading license file `" + file.getAbsolutePath()
                                + "`: " + ex.getMessage(), ex);
                    }
                }
            }
        }
    }

    @Override
    public String toString() {
        return modulePath + ": " + version;
    }
}
