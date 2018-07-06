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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
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
    private String[] filters = null;

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
            final boolean filesMatched = super.getFilesMatched();
            final boolean accepted = super.accept(pathname);
            if (accepted && filters != null && FileContentSearch.contains(pathname, filters)) {
                if (!filesMatched) {
                    super.setFilesMatched(filesMatched);
                }
                return false;
            }
            return accepted;
        } catch (IOException ex) {
            LOGGER.warn(String.format("Error testing file %s", pathname), ex);
        }
        return false;
    }

    /**
     * Initializes the analyzer with the configured settings.
     *
     * @param settings the configured settings to use
     */
    @Override
    public void initialize(Settings settings) {
        super.initialize(settings);
        if (this.isEnabled()) {
            this.filters = settings.getArray(Settings.KEYS.ANALYZER_RETIREJS_FILTERS);
        }
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
        File repoFile = null;
        try {
            repoFile = new File(getSettings().getDataDirectory(), "jsrepository.json");
        } catch (FileNotFoundException ex) {
            this.setEnabled(false);
            throw new InitializationException(String.format("RetireJS repo does not exist locally (%s)", repoFile), ex);
        } catch (IOException ex) {
            this.setEnabled(false);
            throw new InitializationException("Failed to initialize the RetireJS repo - data directory could not be created", ex);
        }
        try (FileInputStream in = new FileInputStream(repoFile)) {
            this.jsRepository = new VulnerabilitiesRepositoryLoader().loadFromInputStream(in);

        } catch (IOException ex) {
            this.setEnabled(false);
            throw new InitializationException("Failed to initialize the RetireJS repo", ex);
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
            final List<JsLibraryResult> results = scanner.scanScript(dependency.getActualFile().getAbsolutePath(), fileContent, 0);

            if (results.size() > 0) {
                for (JsLibraryResult libraryResult : results) {

                    final JsLibrary lib = libraryResult.getLibrary();
                    dependency.setName(lib.getName());
                    dependency.setVersion(libraryResult.getDetectedVersion());
                    dependency.addEvidence(EvidenceType.VERSION, "file", "version", libraryResult.getDetectedVersion(), Confidence.HIGH);
                    dependency.addEvidence(EvidenceType.PRODUCT, "file", "name", libraryResult.getLibrary().getName(), Confidence.HIGH);

                    final List<Vulnerability> vulns = new ArrayList<>();
                    final JsVulnerability jsVuln = libraryResult.getVuln();

                    if (jsVuln.getIdentifiers().containsKey("CVE") || jsVuln.getIdentifiers().containsKey("osvdb")) {
                        /* CVEs and OSVDB are an array of Strings - each one a unique vulnerability.
                         * So the JsVulnerability we are operating on may actually be representing
                         * multiple vulnerabilities. */

                        //TODO - can we refactor this to avoid russian doll syndrome (i.e. nesting)?
                        //CSOFF: NestedForDepth
                        for (Map.Entry<String, List<String>> entry : jsVuln.getIdentifiers().entrySet()) {
                            final String key = entry.getKey();
                            final List<String> value = entry.getValue();
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
                                    final Vulnerability vuln = new Vulnerability();
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
                        //CSON: NestedForDepth
                    } else {
                        final Vulnerability individualVuln = new Vulnerability();
                        /* ISSUE, BUG, etc are all individual vulnerabilities. The result of this
                         * iteration will be one vulnerability. */
                        for (Map.Entry<String, List<String>> entry : jsVuln.getIdentifiers().entrySet()) {
                            final String key = entry.getKey();
                            final List<String> value = entry.getValue();
                            // CSOFF: NeedBraces
                            if (null != key) {
                                switch (key) {
                                    case "issue":
                                        individualVuln.setName(libraryResult.getLibrary().getName() + " issue: " + value.get(0));
                                        individualVuln.addReference(key, key, value.get(0));
                                        break;
                                    case "bug":
                                        individualVuln.setName(libraryResult.getLibrary().getName() + " bug: " + value.get(0));
                                        individualVuln.addReference(key, key, value.get(0));
                                        break;
                                    case "summary":
                                        if (null == individualVuln.getName()) {
                                            individualVuln.setName(value.get(0));
                                        }
                                        individualVuln.setDescription(value.get(0));
                                        break;
                                    case "release":
                                        individualVuln.addReference(key, key, value.get(0));
                                        break;
                                    default:
                                        break;
                                }
                            }
                            // CSON: NeedBraces
                            individualVuln.setSource(Vulnerability.Source.RETIREJS);
                            individualVuln.setUnscoredSeverity(jsVuln.getSeverity());
                            for (String info : jsVuln.getInfo()) {
                                individualVuln.addReference("info", "info", info);
                            }
                        }
                        dependency.addVulnerability(individualVuln);
                    }
                }
            } else if (getSettings().getBoolean(Settings.KEYS.ANALYZER_RETIREJS_FILTER_NON_VULNERABLE, false)) {
                engine.removeDependency(dependency);
            }
        } catch (IOException | DatabaseException e) {
            throw new AnalysisException(e);
        }
    }
}
