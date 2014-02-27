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

import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nexus.NexusSearch;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Analyzer which will attempt to locate a dependency on a Nexus service by SHA-1 digest of the dependency.
 *
 * There are two settings which govern this behavior:
 *
 * <ul>
 * <li>{@link org.owasp.dependencycheck.utils.Settings.KEYS#ANALYZER_NEXUS_ENABLED} determines whether this analyzer is
 * even enabled. This can be overridden by setting the system property.</li>
 * <li>{@link org.owasp.dependencycheck.utils.Settings.KEYS#ANALYZER_NEXUS_URL} the URL to a Nexus service to search by
 * SHA-1. There is an expected <code>%s</code> in this where the SHA-1 will get entered.</li>
 * </ul>
 *
 * @author colezlaw
 */
public class NexusAnalyzer extends AbstractAnalyzer {

    /**
     * The logger
     */
    private static final Logger LOGGER = Logger.getLogger(NexusAnalyzer.class.getName());

    /**
     * The name of the analyzer
     */
    private static final String ANALYZER_NAME = "Nexus Analyzer";

    /**
     * The phase in which the analyzer runs
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The types of files on which this will work.
     */
    private static final Set<String> SUPPORTED_EXTENSIONS = newHashSet("jar");

    /**
     * Whether this is actually enabled. Will get set during initialization.
     */
    private boolean enabled = false;

    /**
     * The Nexus Search to be set up for this analyzer.
     */
    private NexusSearch searcher;

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @throws Exception if there's an error during initialization
     */
    @Override
    public void initialize() throws Exception {
        enabled = Settings.getBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED);
        LOGGER.fine("Initializing Nexus Analyzer");
        LOGGER.fine(String.format("Nexus Analyzer enabled: %s", enabled));
        if (enabled) {
            final String searchUrl = Settings.getString(Settings.KEYS.ANALYZER_NEXUS_URL);
            LOGGER.fine(String.format("Nexus Analyzer URL: %s", searchUrl));
            try {
                searcher = new NexusSearch(new URL(searchUrl));
                if (! searcher.preflightRequest()) {
                    LOGGER.warning("There was an issue getting Nexus status. Disabling analyzer.");
                    enabled = false;
                }
            } catch (MalformedURLException mue) {
                // I know that initialize can throw an exception, but we'll
                // just disable the analyzer if the URL isn't valid
                LOGGER.warning(String.format("Property %s not a valid URL. Nexus Analyzer disabled", searchUrl));
                enabled = false;
            }
        }
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
        // Make a quick exit if this analyzer is disabled
        if (!enabled) {
            return;
        }

        try {
            final MavenArtifact ma = searcher.searchSha1(dependency.getSha1sum());
            if (ma.getGroupId() != null && !"".equals(ma.getGroupId())) {
                dependency.getVendorEvidence().addEvidence("nexus", "groupid", ma.getGroupId(), Confidence.HIGH);
            }
            if (ma.getArtifactId() != null && !"".equals(ma.getArtifactId())) {
                dependency.getProductEvidence().addEvidence("nexus", "artifactid", ma.getArtifactId(), Confidence.HIGH);
            }
            if (ma.getVersion() != null && !"".equals(ma.getVersion())) {
                dependency.getVersionEvidence().addEvidence("nexus", "version", ma.getVersion(), Confidence.HIGH);
            }
            if (ma.getArtifactUrl() != null && !"".equals(ma.getArtifactUrl())) {
                dependency.addIdentifier("maven", ma.toString(), ma.getArtifactUrl(), Confidence.HIGHEST);
            }
        } catch (IllegalArgumentException iae) {
            //dependency.addAnalysisException(new AnalysisException("Invalid SHA-1"));
            LOGGER.info(String.format("invalid sha-1 hash on %s", dependency.getFileName()));
        } catch (FileNotFoundException fnfe) {
            //dependency.addAnalysisException(new AnalysisException("Artifact not found on repository"));
            LOGGER.fine(String.format("Artificat not found in repository '%s'", dependency.getFileName()));
            LOGGER.log(Level.FINE, fnfe.getMessage(), fnfe);
        } catch (IOException ioe) {
            //dependency.addAnalysisException(new AnalysisException("Could not connect to repository", ioe));
            LOGGER.log(Level.FINE, "Could not connect to nexus repository", ioe);
        }
    }
}

// vim: cc=120:sw=4:ts=4:sts=4
