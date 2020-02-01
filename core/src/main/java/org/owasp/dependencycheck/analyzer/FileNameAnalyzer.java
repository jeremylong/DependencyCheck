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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import javax.annotation.concurrent.ThreadSafe;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOCase;
import org.apache.commons.io.filefilter.NameFileFilter;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Takes a dependency and analyzes the filename and determines the hashes.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class FileNameAnalyzer extends AbstractAnalyzer {

    /**
     * Python init files
     */
    //CSOFF: WhitespaceAfter
    private static final NameFileFilter IGNORED_FILES = new NameFileFilter(new String[]{
        "__init__.py",
        "__init__.pyc",
        "__init__.pyo",
        "composer.lock",
        "configure.in",
        "configure.ac",
        "Gemfile.lock",
        "METADATA",
        "PKG-INFO",
        "package.json",
        "packages.config",
        "Package.swift",
        "classes.jar",
        "build.gradle",
        "CMakeLists.txt"}, IOCase.INSENSITIVE);
    //CSON: WhitespaceAfter

    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "File Name Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

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
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_FILE_NAME_ENABLED;
    }
    //</editor-fold>

    /**
     * Collects information about the file name.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        //strip any path information that may get added by ArchiveAnalyzer, etc.
        final File f = dependency.getActualFile();
        final String fileName = FilenameUtils.removeExtension(f.getName());
        final String ext = FilenameUtils.getExtension(f.getName());
        if (!IGNORED_FILES.accept(f) && !"js".equals(ext)) {
            //add version evidence
            final DependencyVersion version = DependencyVersionUtil.parseVersion(fileName);
            final String packageName = DependencyVersionUtil.parsePreVersion(fileName);

            if (version != null) {
                // If the version number is just a number like 2 or 23, reduce the confidence
                // a shade. This should hopefully correct for cases like log4j.jar or
                // struts2-core.jar
                if (version.getVersionParts() == null || version.getVersionParts().size() < 2) {
                    dependency.addEvidence(EvidenceType.VERSION, "file", "version", version.toString(), Confidence.MEDIUM);
                } else {
                    dependency.addEvidence(EvidenceType.VERSION, "file", "version", version.toString(), Confidence.HIGH);
                }
                dependency.addEvidence(EvidenceType.VERSION, "file", "name", packageName, Confidence.MEDIUM);
            }

            dependency.addEvidence(EvidenceType.PRODUCT, "file", "name", packageName, Confidence.HIGH);
            dependency.addEvidence(EvidenceType.VENDOR, "file", "name", packageName, Confidence.HIGH);
        }
    }
}
