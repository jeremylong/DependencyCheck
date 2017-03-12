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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nuget.NugetPackage;
import org.owasp.dependencycheck.data.nuget.NuspecParseException;
import org.owasp.dependencycheck.data.nuget.NuspecParser;
import org.owasp.dependencycheck.data.nuget.XPathNuspecParser;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import org.owasp.dependencycheck.exception.InitializationException;

/**
 * Analyzer which will parse a Nuspec file to gather module information.
 *
 * @author colezlaw
 */
public class NuspecAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NuspecAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Nuspec Analyzer";

    /**
     * The phase in which the analyzer runs.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The types of files on which this will work.
     */
    private static final String SUPPORTED_EXTENSIONS = "nuspec";

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    public void initializeFileTypeAnalyzer() throws InitializationException {
    }

    /**
     * Returns the analyzer's name.
     *
     * @return the name of the analyzer
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NUSPEC_ENABLED;
    }

    /**
     * Returns the analysis phase under which the analyzer runs.
     *
     * @return the phase under which this analyzer runs
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(
            SUPPORTED_EXTENSIONS).build();

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Performs the analysis.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine
     * @throws AnalysisException when there's an exception during analysis
     */
    @Override
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        LOGGER.debug("Checking Nuspec file {}", dependency);
        try {
            final NuspecParser parser = new XPathNuspecParser();
            NugetPackage np = null;
            try (FileInputStream fis = new FileInputStream(dependency.getActualFilePath())) {
                np = parser.parse(fis);
            } catch (NuspecParseException | FileNotFoundException ex) {
                throw new AnalysisException(ex);
            }

            if (np.getOwners() != null) {
                dependency.getVendorEvidence().addEvidence("nuspec", "owners", np.getOwners(), Confidence.HIGHEST);
            }
            dependency.getVendorEvidence().addEvidence("nuspec", "authors", np.getAuthors(), Confidence.HIGH);
            dependency.getVersionEvidence().addEvidence("nuspec", "version", np.getVersion(), Confidence.HIGHEST);
            dependency.getProductEvidence().addEvidence("nuspec", "id", np.getId(), Confidence.HIGHEST);
            if (np.getTitle() != null) {
                dependency.getProductEvidence().addEvidence("nuspec", "title", np.getTitle(), Confidence.MEDIUM);
            }
        } catch (Throwable e) {
            throw new AnalysisException(e);
        }
    }
}
