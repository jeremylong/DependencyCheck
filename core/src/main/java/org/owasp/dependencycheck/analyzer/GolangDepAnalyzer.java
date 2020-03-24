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
 * Copyright (c) 2019 Nima Yahyazadeh. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import java.io.FileFilter;
import java.util.List;

import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;

import com.moandjiezana.toml.Toml;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.data.nvd.ecosystem.Ecosystem;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.Checksum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Go lang dependency analyzer.
 *
 * @author Nima Yahyazadeh
 * @author Jeremy Long
 */
@ThreadSafe
@Experimental
public class GolangDepAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GolangDepAnalyzer.class);
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = Ecosystem.GOLANG;

    /**
     * Lock file name.
     */
    private static final String GOPKG_LOCK = "Gopkg.lock";

    /**
     * The file filter for Gopkg.lock
     */
    private static final FileFilter GOPKG_LOCK_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(GOPKG_LOCK)
            .build();

    /**
     * Returns the name of the Python Package Analyzer.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return "Golang Dep Analyzer";
    }

    /**
     * Tell that we are used for information collection.
     *
     * @return INFORMATION_COLLECTION
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.INFORMATION_COLLECTION;
    }

    /**
     * Returns the key name for the analyzers enabled setting.
     *
     * @return the key name for the analyzers enabled setting
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_GOLANG_DEP_ENABLED;
    }

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return GOPKG_LOCK_FILTER;
    }

    /**
     * No-op initializer implementation.
     *
     * @param engine a reference to the dependency-check engine
     *
     * @throws InitializationException never thrown
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        // Nothing to do here.
    }

    /**
     * Analyzes go packages and adds evidence to the dependency.
     *
     * @param dependency the dependency being analyzed
     * @param engine the engine being used to perform the scan
     *
     * @throws AnalysisException thrown if there is an unrecoverable error
     * analyzing the dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        //do not report on the build file itself
        engine.removeDependency(dependency);

        final Toml result = new Toml().read(dependency.getActualFile());
        final List<Toml> projectsLocks = result.getTables("projects");
        if (projectsLocks == null) {
            return;
        }
        projectsLocks.forEach((project) -> {
            final String name = project.getString("name");
            final String version = project.getString("version");
            final String revision = project.getString("revision");

            Dependency dep = createDependency(dependency, name, version, revision, null);
            engine.addDependency(dep);
            final List<String> packages = project.getList("packages");
            for (String pkg : packages) {
                if (StringUtils.isNotBlank(pkg) && !".".equals(pkg)) {
                    dep = createDependency(dependency, name, version, revision, pkg);
                    engine.addDependency(dep);
                }
            }
        });
    }

    /**
     * Builds a dependency object based on the given data.
     *
     * @param parentDependency a reference to the parent dependency
     * @param name the name of the dependency
     * @param version the version of the dependency
     * @param revision the revision of the dependency
     * @param subPath the sub-path of the dependency
     * @return a new dependency object
     */
    private Dependency createDependency(Dependency parentDependency, String name, String version, String revision, String subPath) {
        final Dependency dep = new Dependency(parentDependency.getActualFile(), true);
        dep.setEcosystem(DEPENDENCY_ECOSYSTEM);
        if (StringUtils.isNotBlank(subPath)) {
            dep.setDisplayFileName(name + "/" + subPath);
            dep.setName(name + "/" + subPath);
        } else {
            dep.setDisplayFileName(name);
            dep.setName(name);
        }
        final PackageURLBuilder packageBuilder = PackageURLBuilder.aPackageURL().withType("golang");

        String baseNamespace = null;
        String depNamespace = null;
        String depName = null;
        if (StringUtils.isNotBlank(name)) {
            final int slashPos = name.indexOf("/");
            if (slashPos > 0) {
                baseNamespace = name.substring(0, slashPos);
                final int lastSlash = name.lastIndexOf("/");
                depName = name.substring(lastSlash + 1);
                if (lastSlash != slashPos) {
                    depNamespace = name.substring(slashPos + 1, lastSlash);
                    dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "namespace", depNamespace, Confidence.HIGH);
                    dep.addEvidence(EvidenceType.VENDOR, GOPKG_LOCK, "namespace", depNamespace, Confidence.HIGH);
                    packageBuilder.withNamespace(baseNamespace + "/" + depNamespace);
                } else {
                    packageBuilder.withNamespace(baseNamespace);
                }
                packageBuilder.withName(depName);
                if (!"golang.org".equals(baseNamespace)) {
                    dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "namespace", baseNamespace, Confidence.LOW);
                    dep.addEvidence(EvidenceType.VENDOR, GOPKG_LOCK, "namespace", baseNamespace, Confidence.LOW);
                }

                dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "name", depName, Confidence.HIGHEST);
                dep.addEvidence(EvidenceType.VENDOR, GOPKG_LOCK, "name", depName, Confidence.HIGHEST);
            } else {
                packageBuilder.withName(name);
                dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "namespace", name, Confidence.HIGHEST);
                dep.addEvidence(EvidenceType.VENDOR, GOPKG_LOCK, "namespace", name, Confidence.HIGHEST);
            }
        }
        if (StringUtils.isNotBlank(version)) {
            packageBuilder.withVersion(version);
            dep.setVersion(version);
            dep.addEvidence(EvidenceType.VERSION, GOPKG_LOCK, "version", version, Confidence.HIGHEST);
        }
        if (StringUtils.isNotBlank(revision)) {
            if (version == null) {
                //this is used to help determine the actual version in the NVD - a commit hash doesn't work
                // instead we need to make it an asterik for the CPE...
                //dep.setVersion(revision);
                packageBuilder.withVersion(revision);
            }
            //Revision (which appears to be a commit hash) won't be of any value in the analysis.
            //dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "revision", revision, Confidence.HIGHEST);
        }
        if (StringUtils.isNotBlank(subPath)) {
            packageBuilder.withSubpath(subPath);
            dep.addEvidence(EvidenceType.PRODUCT, GOPKG_LOCK, "package", subPath, Confidence.HIGH);
            dep.addEvidence(EvidenceType.VENDOR, GOPKG_LOCK, "package", subPath, Confidence.MEDIUM);
        }

        Identifier id;
        try {
            final PackageURL purl = packageBuilder.build();
            id = new PurlIdentifier(purl, Confidence.HIGHEST);
        } catch (MalformedPackageURLException ex) {
            LOGGER.warn("Unable to create package-url identifier for `{}` in `{}` - reason: {}",
                    name, parentDependency.getFilePath(), ex.getMessage());
            final StringBuilder value = new StringBuilder(name);
            if (StringUtils.isNotBlank(subPath)) {
                value.append("/").append(subPath);
            }
            if (StringUtils.isNotBlank(version)) {
                value.append("@").append(version);
            }
            id = new GenericIdentifier(value.toString(), Confidence.HIGH);
        }
        dep.addSoftwareIdentifier(id);
        dep.setSha1sum(Checksum.getSHA1Checksum(id.toString()));
        dep.setMd5sum(Checksum.getMD5Checksum(id.toString()));
        dep.setSha256sum(Checksum.getSHA256Checksum(id.toString()));

        return dep;
    }
}
