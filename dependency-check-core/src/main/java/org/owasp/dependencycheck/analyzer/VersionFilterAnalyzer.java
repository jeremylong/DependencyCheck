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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.Iterator;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This analyzer attempts to filter out erroneous version numbers collected.
 * Initially, this will focus on JAR files that contain a POM version number
 * that matches the file name - if identified all other version information will
 * be removed.
 *
 * @author Jeremy Long
 */
public class VersionFilterAnalyzer extends AbstractAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Version Filter Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.POST_INFORMATION_COLLECTION;

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
     * Returns the setting key to determine if the analyzer is enabled.
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_VERSION_FILTER_ENABLED;
    }
    //</editor-fold>

    /**
     * The Logger for use throughout the class
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(VersionFilterAnalyzer.class);

    /**
     * The HintAnalyzer uses knowledge about a dependency to add additional
     * information to help in identification of identifiers or vulnerabilities.
     *
     * @param dependency The dependency being analyzed
     * @param engine The scanning engine
     * @throws AnalysisException is thrown if there is an exception analyzing
     * the dependency.
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        String fileVersion = null;
        String pomVersion = null;
        for (Evidence e : dependency.getVersionEvidence()) {
            if ("file".equals(e.getSource()) && "version".equals(e.getName())) {
                fileVersion = e.getValue(Boolean.FALSE);
            } else if (("nexus".equals(e.getSource()) || "central".equals(e.getSource())
                    || "pom".equals(e.getSource())) && "version".equals(e.getName())) {
                pomVersion = e.getValue(Boolean.FALSE);
            }
        }
        if (fileVersion != null && pomVersion != null) {
            final DependencyVersion dvFile = new DependencyVersion(fileVersion);
            final DependencyVersion dvPom = new DependencyVersion(pomVersion);
            if (dvPom.equals(dvFile)) {
                LOGGER.debug("filtering evidence from {}", dependency.getFileName());
                final EvidenceCollection versionEvidence = dependency.getVersionEvidence();
                synchronized (versionEvidence) {
                    final Iterator<Evidence> itr = versionEvidence.iterator();
                    while (itr.hasNext()) {
                        final Evidence e = itr.next();
                        if (!("version".equals(e.getName())
                                && ("file".equals(e.getSource())
                                || "nexus".equals(e.getSource())
                                || "central".equals(e.getSource())
                                || "pom".equals(e.getSource())))) {
                            itr.remove();
                        }
                    }
                }
            }
        }
    }
}
