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

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.central.CentralSearch;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.xml.pom.PomUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Analyzer which will attempt to locate a dependency, and the GAV information,
 * by querying Central for the dependency's SHA-1 digest.
 *
 * @author colezlaw
 */
@ThreadSafe
public class CentralAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CentralAnalyzer.class);

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Central Analyzer";

    /**
     * The phase in which this analyzer runs.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;

    /**
     * The types of files on which this will work.
     */
    private static final String SUPPORTED_EXTENSIONS = "jar";

    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(SUPPORTED_EXTENSIONS).build();

    /**
     * The base wait time between retrying a failed connection to Central.
     */
    private static final int BASE_RETRY_WAIT = 1500;
    /**
     * There may be temporary issues when connecting to MavenCentral. In order
     * to compensate for 99% of the issues, we perform a retry before finally
     * failing the analysis.
     */
    private static int numberOfRetries = 7;

    /**
     * The searcher itself.
     */
    private CentralSearch searcher;

    /**
     * Initializes the analyzer with the configured settings.
     *
     * @param settings the configured settings to use
     */
    @Override
    public synchronized void initialize(Settings settings) {
        super.initialize(settings);
        setEnabled(checkEnabled());
        numberOfRetries = getSettings().getInt(Settings.KEYS.ANALYZER_CENTRAL_RETRY_COUNT, numberOfRetries);
    }

    /**
     * Whether the analyzer is configured to support parallel processing.
     *
     * @return true if configured to support parallel processing; otherwise
     * false
     */
    @Override
    public boolean supportsParallelProcessing() {
        try {
            return getSettings().getBoolean(Settings.KEYS.ANALYZER_CENTRAL_PARALLEL_ANALYSIS, true);
        } catch (InvalidSettingException ex) {
            LOGGER.debug("Invalid setting for analyzer.central.parallel.analysis; using true.");
        }
        return true;
    }

    /**
     * Determines if this analyzer is enabled.
     *
     * @return <code>true</code> if the analyzer is enabled; otherwise
     * <code>false</code>
     */
    private boolean checkEnabled() {
        boolean retVal = false;

        try {
            if (getSettings().getBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED)) {
                if (!getSettings().getBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED)
                        || NexusAnalyzer.DEFAULT_URL.equals(getSettings().getString(Settings.KEYS.ANALYZER_NEXUS_URL))) {
                    LOGGER.debug("Enabling the Central analyzer");
                    retVal = true;
                } else {
                    LOGGER.info("Nexus analyzer is enabled, disabling the Central Analyzer");
                }
            } else {
                LOGGER.info("Central analyzer disabled");
            }
        } catch (InvalidSettingException ise) {
            LOGGER.warn("Invalid setting. Disabling the Central analyzer");
        }
        return retVal;
    }

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        LOGGER.debug("Initializing Central analyzer");
        LOGGER.debug("Central analyzer enabled: {}", isEnabled());
        if (isEnabled()) {
            try {
                searcher = new CentralSearch(getSettings());
            } catch (MalformedURLException ex) {
                setEnabled(false);
                throw new InitializationException("The configured URL to Maven Central is malformed", ex);
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
     * Returns the key used in the properties file to to reference the
     * analyzer's enabled property.
     *
     * @return the analyzer's enabled property setting key.
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CENTRAL_ENABLED;
    }

    /**
     * Returns the analysis phase under which the analyzer runs.
     *
     * @return the phase under which the analyzer runs
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

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
        for (Evidence e : dependency.getEvidence(EvidenceType.VENDOR)) {
            if ("pom".equals(e.getSource())) {
                return;
            }
        }
        try {
            final List<MavenArtifact> mas = fetchMavenArtifacts(dependency);
            final Confidence confidence = mas.size() > 1 ? Confidence.HIGH : Confidence.HIGHEST;
            for (MavenArtifact ma : mas) {
                LOGGER.debug("Central analyzer found artifact ({}) for dependency ({})", ma, dependency.getFileName());
                dependency.addAsEvidence("central", ma, confidence);

                if (ma.getPomUrl() != null) {
                    File pomFile = null;
                    try {
                        final File baseDir = getSettings().getTempDirectory();
                        pomFile = File.createTempFile("pom", ".xml", baseDir);
                        if (!pomFile.delete()) {
                            LOGGER.warn("Unable to fetch pom.xml for {} from Central; "
                                    + "this could result in undetected CPE/CVEs.", dependency.getFileName());
                            LOGGER.debug("Unable to delete temp file");
                        }
                        LOGGER.debug("Downloading {}", ma.getPomUrl());
                        final Downloader downloader = new Downloader(getSettings());
                        final int maxAttempts = this.getSettings().getInt(Settings.KEYS.ANALYZER_CENTRAL_RETRY_COUNT, 3);
                        int retryCount = 0;
                        long sleepingTimeBetweenRetriesInMillis = BASE_RETRY_WAIT;
                        boolean success = false;
                        do {
                            //CSOFF: NestedTryDepth
                            try {
                                downloader.fetchFile(new URL(ma.getPomUrl()), pomFile);
                                success = true;
                            } catch (DownloadFailedException ex) {
                                try {
                                    Thread.sleep(sleepingTimeBetweenRetriesInMillis);
                                    sleepingTimeBetweenRetriesInMillis *= 2;
                                } catch (InterruptedException ex1) {
                                    throw new RuntimeException(ex1);
                                }
                            }
                            //CSON: NestedTryDepth
                        } while (!success && retryCount++ < maxAttempts);
                        PomUtils.analyzePOM(dependency, pomFile);

                    } catch (DownloadFailedException ex) {
                        LOGGER.warn("Unable to download pom.xml for {} from Central; "
                                + "this could result in undetected CPE/CVEs.", dependency.getFileName());

                    } finally {
                        if (pomFile != null && pomFile.exists() && !FileUtils.deleteQuietly(pomFile)) {
                            LOGGER.debug("Failed to delete temporary pom file {}", pomFile.toString());
                            pomFile.deleteOnExit();
                        }
                    }
                }
            }
        } catch (IllegalArgumentException iae) {
            LOGGER.info("invalid sha1-hash on {}", dependency.getFileName());
        } catch (FileNotFoundException fnfe) {
            LOGGER.debug("Artifact not found in repository: '{}", dependency.getFileName());
        } catch (IOException ioe) {
            final String message = "Could not connect to Central search. Analysis failed.";
            LOGGER.error(message, ioe);
            throw new AnalysisException(message, ioe);
        }
    }

    /**
     * Downloads the corresponding list of MavenArtifacts of the given
     * dependency from MavenCentral.
     * <p>
     * As the connection to MavenCentral is known to be unreliable, we implement
     * a simple retry logic in order to compensate for 99% of the issues.
     *
     * @param dependency the dependency to analyze
     * @return the downloaded list of MavenArtifacts
     * @throws FileNotFoundException if the specified artifact is not found
     * @throws IOException if connecting to MavenCentral finally failed
     */
    protected List<MavenArtifact> fetchMavenArtifacts(Dependency dependency) throws IOException {
        IOException lastException = null;
        long sleepingTimeBetweenRetriesInMillis = BASE_RETRY_WAIT;
        int triesLeft = numberOfRetries;
        while (triesLeft-- > 0) {
            try {
                return searcher.searchSha1(dependency.getSha1sum());
            } catch (FileNotFoundException fnfe) {
                // retry does not make sense, just throw the exception
                throw fnfe;
            } catch (IOException ioe) {
                LOGGER.debug("Could not connect to Central search (tries left: {}): {}",
                        triesLeft, ioe.getMessage());
                lastException = ioe;

                if (triesLeft > 0) {
                    try {
                        Thread.sleep(sleepingTimeBetweenRetriesInMillis);
                        sleepingTimeBetweenRetriesInMillis *= 2;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }

        final String message = "Finally failed connecting to Central search."
                + " Giving up after " + numberOfRetries + " tries.";
        throw new IOException(message, lastException);
    }

    /**
     * Method used by unit tests to setup the analyzer.
     *
     * @param searcher the Central Search object to use.
     */
    protected void setCentralSearch(CentralSearch searcher) {
        this.searcher = searcher;
    }
}
