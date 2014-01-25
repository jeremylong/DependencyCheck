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

import java.io.File;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nuget.NuspecHandler;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 * Analyzer which will parse a Nuspec file to gather module information.
 *
 * @author colezlaw
 */
public class NuspecAnalyzer extends AbstractAnalyzer {

    /**
     * The logger
     */
    private static final Logger LOGGER = Logger.getLogger(NuspecAnalyzer.class.getName());

    /**
     * The name of the analyzer
     */
    private static final String ANALYZER_NAME = "Nuspec Analyzer";

    /**
     * The phase in which the analyzer runs
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The types of files on which this will work.
     */
    private static final Set<String> SUPPORTED_EXTENSIONS = newHashSet("nuspec");

    /**
     * The SAXParser we'll use to parse nuspec files.
     */
    private SAXParser parser;

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @throws Exception if there's an error during initialization
     */
    @Override
    public void initialize() throws Exception {
        final SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setNamespaceAware(true);
        parser = factory.newSAXParser();
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
     * Returns the analysis phase under which the analyzer runs.
     *
     * @return the phase under which this analyzer runs
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * Returns the extensions for which this Analyzer runs.
     *
     * @return the extensions for which this Analyzer runs
     */
    @Override
    public Set<String> getSupportedExtensions() {
        return SUPPORTED_EXTENSIONS;
    }

    /**
     * Determines whether the incoming extension is supported.
     *
     * @param extension the extension to check for support
     * @return whether the extension is supported
     */
    @Override
    public boolean supportsExtension(String extension) {
        return SUPPORTED_EXTENSIONS.contains(extension);
    }

    /**
     * Performs the analysis.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine
     * @throws AnalysisException when there's an exception during analysis
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        LOGGER.log(Level.INFO, "Checking Nuspec file {0}", dependency.toString());
        try {
            final NuspecHandler nh = new NuspecHandler();
            parser.parse(new File(dependency.getActualFilePath()), nh);
            if (nh.getVersion() != null && !"".equals(nh.getVersion())) {
                dependency.getVersionEvidence().addEvidence("nuspec", "version", nh.getVersion(),
                                                            Confidence.HIGHEST);
            }
            if (nh.getId() != null && !"".equals(nh.getId())) {
                dependency.getProductEvidence().addEvidence("nuspec", "id", nh.getId(),
                                                            Confidence.HIGHEST);
            }
            if (nh.getOwners() != null && !"".equals(nh.getOwners())) {
                dependency.getVendorEvidence().addEvidence("nuspec", "owners", nh.getOwners(),
                                                           Confidence.HIGHEST);
            }
            if (nh.getAuthors() != null && !"".equals(nh.getAuthors())) {
                dependency.getVendorEvidence().addEvidence("nuspec", "authors", nh.getAuthors(),
                                                           Confidence.MEDIUM);
            }
            if (nh.getTitle() != null && !"".equals(nh.getTitle())) {
                dependency.getProductEvidence().addEvidence("nuspec", "title", nh.getTitle(),
                                                            Confidence.MEDIUM);
            }
            if (nh.getLicenseUrl() != null && !"".equals(nh.getLicenseUrl())) {
                dependency.setLicense(nh.getLicenseUrl());
            }
        } catch (Exception e) {
            throw new AnalysisException(e);
        }
    }
}

// vim: cc=120:sw=4:ts=4:sts=4
