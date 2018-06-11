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
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import com.h3xstream.retirejs.repo.JsLibrary;
import com.h3xstream.retirejs.repo.JsLibraryResult;
import com.h3xstream.retirejs.repo.JsVulnerability;
import com.h3xstream.retirejs.repo.ScannerFacade;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepository;
import com.h3xstream.retirejs.repo.VulnerabilitiesRepositoryLoader;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.search.FileContentSearch;

/**
 * The RetireJS analyzer uses the manually curated list of vulnerabilities from
 * the RetireJS community along with the necessary information to assist in
 * identifying vulnerable components. Vulnerabilities documented by the RetireJS
 * community usually originate from other sources such as the NVD, OSVDB, NSP,
 * and various issue trackers.
 *
 * @author Steve Springett
 */
@ThreadSafe
@Experimental
public class RetireJsAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RetireJsAnalyzer.class);
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = "js";
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "RetireJS Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.FINDING_ANALYSIS;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final String[] EXTENSIONS = {"js"};
    /**
     * The file filter used to determine which files this analyzer supports.
     */
    private static final FileFilter FILTER = FileFilterBuilder.newInstance().addExtensions(EXTENSIONS).build();
    /**
     * An instance of the local VulnerabilitiesRepository
     */
    private VulnerabilitiesRepository jsRepository;
    /**
     * The list of filters used to exclude files by file content; the intent is
     * that this could be used to filter out a companies custom files by filter
     * on their own copyright statements.
     */
    private List<String> filters = null;

    /**
     * Flag indicating whether non-vulnerable JS should be excluded if they are
     * contained in a JAR.
     */
    private boolean skipNonVulnerableInJAR = true;

    /**
     * Returns the FileFilter.
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return FILTER;
    }

    /**
     * Determines if the file can be analyzed by the analyzer.
     *
     * @param pathname the path to the file
     * @return true if the file can be analyzed by the given analyzer; otherwise
     * false
     */
    @Override
    public boolean accept(File pathname) {
        try {
            boolean accepted = super.accept(pathname);
            if (accepted && filters != null && FileContentSearch.contains(pathname, filters)) {
                return false;
            }
            return accepted;
        } catch (IOException ex) {
            LOGGER.warn(String.format("Error testing file %s", pathname), ex);
        }
        return false;        
    }

    /**
     * {@inheritDoc}
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if there is an exception during
     * initialization
     */
    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {

        final Settings settings = engine.getSettings();
        try {
            initializeRetireJsRepo(engine, new URL(settings.getString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, DEFAULT_JS_URL)));
        } catch (MalformedURLException e) {
            throw new InitializationException("A URL to the RetireJS repositories is invalid", e);
        }
    }

    /**
     * Initializes the local RetireJS repository
     *
     * @param engine a reference to the dependency-check engine
     * @param repoUrl the URL to the RetireJS repo to use
     * @throws InitializationException thrown if there is an exception during
     * initialization
     */
    private void initializeRetireJsRepo(Engine engine, URL repoUrl) throws InitializationException {
        //TODO put the following code into a CachedWebDataSource
        try {
            File dataDir = engine.getSettings().getDataDirectory();
            Settings settings = engine.getSettings();
            boolean useProxy = false;
            if (null != settings.getString(Settings.KEYS.PROXY_SERVER)) {
                useProxy = true;
                LOGGER.debug("Using proxy");
            }
            LOGGER.debug("RetireJS Repo URL: {}", repoUrl.toExternalForm());
            final URLConnectionFactory factory = new URLConnectionFactory(settings);
            final HttpURLConnection conn = factory.createHttpURLConnection(repoUrl, useProxy);
            String filename = repoUrl.getFile().substring(repoUrl.getFile().lastIndexOf("/") + 1, repoUrl.getFile().length());
            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                File repoFile = new File(dataDir, filename);
                try (InputStream inputStream = conn.getInputStream();
                        FileOutputStream outputStream = new FileOutputStream(repoFile)) {

                    int bytesRead;
                    byte[] buffer = new byte[4096];
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                }
            }
            File repoFile = new File(engine.getSettings().getDataDirectory(), "jsrepository.json");
            this.jsRepository = new VulnerabilitiesRepositoryLoader().loadFromInputStream(new FileInputStream(repoFile));
        } catch (IOException e) {
            throw new InitializationException("Failed to initialize the RetireJS repo", e);
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
     * Returns the key used in the properties file to reference the analyzer's
     * enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_RETIREJS_ENABLED;
    }

    /**
     * Analyzes the specified JavaScript file.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the file
     * file.
     */
    @Override
    public void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            final byte[] fileContent = IOUtils.toByteArray(new FileInputStream(dependency.getActualFile()));
            final ScannerFacade scanner = new ScannerFacade(jsRepository);
            List<JsLibraryResult> results = scanner.scanScript(dependency.getActualFile().getAbsolutePath(), fileContent, 0);

            if (results.size() > 0) {
                for (JsLibraryResult libraryResult : results) {

                    JsLibrary lib = libraryResult.getLibrary();
                    dependency.setName(lib.getName());
                    dependency.setVersion(libraryResult.getDetectedVersion());
                    dependency.addEvidence(EvidenceType.VERSION, "file", "version", libraryResult.getDetectedVersion(), Confidence.HIGH);
                    dependency.addEvidence(EvidenceType.PRODUCT, "file", "name", libraryResult.getLibrary().getName(), Confidence.HIGH);

                    List<Vulnerability> vulns = new ArrayList<>();
                    JsVulnerability jsVuln = libraryResult.getVuln();

                    if (jsVuln.getIdentifiers().containsKey("CVE") || jsVuln.getIdentifiers().containsKey("osvdb")) {
                        /* CVEs and OSVDB are an array of Strings - each one a unique vulnerability.
                         * So the JsVulnerability we are operating on may actually be representing
                         * multiple vulnerabilities. */
                        for (Map.Entry<String, List<String>> entry : jsVuln.getIdentifiers().entrySet()) {
                            String key = entry.getKey();
                            List<String> value = entry.getValue();
                            if ("CVE".equals(key)) {
                                for (String cve : value) {
                                    Vulnerability vuln = engine.getDatabase().getVulnerability(StringUtils.trim(cve));
                                    if (vuln == null) {
                                        /* The CVE does not exist in the database and is likely in a
                                         * reserved state. Create a new one without adding it to the
                                         * database and populate it as best as possible. */
                                        vuln = new Vulnerability();
                                        vuln.setName(cve);
                                        vuln.setUnscoredSeverity(jsVuln.getSeverity());
                                        vuln.setSource(Vulnerability.Source.RETIREJS);
                                    }
                                    for (String info : jsVuln.getInfo()) {
                                        vuln.addReference("info", "info", info);
                                    }
                                    vulns.add(vuln);
                                }
                            } else if ("osvdb".equals(key)) {
                                for (String osvdb : value) {
                                    Vulnerability vuln = new Vulnerability();
                                    vuln.setName(osvdb);
                                    vuln.setSource(Vulnerability.Source.RETIREJS);
                                    vuln.setUnscoredSeverity(jsVuln.getSeverity());
                                    for (String info : jsVuln.getInfo()) {
                                        vuln.addReference("info", "info", info);
                                    }
                                    vulns.add(vuln);
                                }
                            }
                            dependency.addVulnerabilities(vulns);
                        }
                    } else {
                        Vulnerability individualVuln = new Vulnerability();
                        /* ISSUE, BUG, etc are all individual vulnerabilities. The result of this
                         * iteration will be one vulnerability. */
                        for (Map.Entry<String, List<String>> entry : jsVuln.getIdentifiers().entrySet()) {
                            String key = entry.getKey();
                            List<String> value = entry.getValue();
                            if ("issue".equals(key)) {
                                individualVuln.setName(libraryResult.getLibrary().getName() + " issue: " + value.get(0));
                                individualVuln.addReference(key, key, value.get(0));
                            } else if ("bug".equals(key)) {
                                individualVuln.setName(libraryResult.getLibrary().getName() + " bug: " + value.get(0));
                                individualVuln.addReference(key, key, value.get(0));
                            } else if ("summary".equals(key)) {
                                if (null == individualVuln.getName()) {
                                    individualVuln.setName(value.get(0));
                                }
                                individualVuln.setDescription(value.get(0));
                            } else if ("release".equals(key)) {
                                individualVuln.addReference(key, key, value.get(0));
                            }
                            individualVuln.setSource(Vulnerability.Source.RETIREJS);
                            individualVuln.setUnscoredSeverity(jsVuln.getSeverity());
                            for (String info : jsVuln.getInfo()) {
                                individualVuln.addReference("info", "info", info);
                            }
                        }
                        dependency.addVulnerability(individualVuln);
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
