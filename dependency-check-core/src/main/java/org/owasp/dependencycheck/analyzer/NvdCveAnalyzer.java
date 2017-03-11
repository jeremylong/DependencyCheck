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

import java.io.IOException;
import java.sql.SQLException;
import java.util.List;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.LoggerFactory;

/**
 * NvdCveAnalyzer is a utility class that takes a project dependency and
 * attempts to discern if there is an associated CVEs. It uses the the
 * identifiers found by other analyzers to lookup the CVE data.
 *
 * @author Jeremy Long
 */
public class NvdCveAnalyzer extends AbstractAnalyzer {

    /**
     * The Logger for use throughout the class
     */
    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(NvdCveAnalyzer.class);

    /**
     * The CVE Index.
     */
    private CveDB cveDB;

    /**
     * Opens the data source.
     *
     * @throws SQLException thrown when there is a SQL Exception
     * @throws IOException thrown when there is an IO Exception
     * @throws DatabaseException thrown when there is a database exceptions
     * @throws ClassNotFoundException thrown if the h2 database driver cannot be
     * loaded
     */
    public void open() throws SQLException, IOException, DatabaseException, ClassNotFoundException {
        cveDB = CveDB.getInstance();
    }

    /**
     * Closes the data source.
     */
    @Override
    public void closeAnalyzer() {
        cveDB = null;
    }

    /**
     * Returns the status of the data source - is the database open.
     *
     * @return true or false.
     */
    public boolean isOpen() {
        return cveDB != null;
    }

    /**
     * Analyzes a dependency and attempts to determine if there are any CPE
     * identifiers for this dependency.
     *
     * @param dependency The Dependency to analyze
     * @param engine The analysis engine
     * @throws AnalysisException thrown if there is an issue analyzing the
     * dependency
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        for (Identifier id : dependency.getIdentifiers()) {
            if ("cpe".equals(id.getType())) {
                try {
                    final String value = id.getValue();
                    final List<Vulnerability> vulns = cveDB.getVulnerabilities(value);
                    dependency.getVulnerabilities().addAll(vulns);
                } catch (DatabaseException ex) {
                    throw new AnalysisException(ex);
                }
            }
        }
        for (Identifier id : dependency.getSuppressedIdentifiers()) {
            if ("cpe".equals(id.getType())) {
                try {
                    final String value = id.getValue();
                    final List<Vulnerability> vulns = cveDB.getVulnerabilities(value);
                    dependency.getSuppressedVulnerabilities().addAll(vulns);
                } catch (DatabaseException ex) {
                    throw new AnalysisException(ex);
                }
            }
        }
    }

    /**
     * Returns the name of this analyzer.
     *
     * @return the name of this analyzer.
     */
    @Override
    public String getName() {
        return "NVD CVE Analyzer";
    }

    /**
     * Returns the analysis phase that this analyzer should run in.
     *
     * @return the analysis phase that this analyzer should run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
    }

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NVD_CVE_ENABLED;
    }

    /**
     * Opens the database used to gather NVD CVE data.
     *
     * @throws InitializationException is thrown if there is an issue opening
     * the index.
     */
    @Override
    public void initializeAnalyzer() throws InitializationException {
        try {
            this.open();
        } catch (SQLException ex) {
            LOGGER.debug("SQL Exception initializing NvdCveAnalyzer", ex);
            throw new InitializationException(ex);
        } catch (IOException ex) {
            LOGGER.debug("IO Exception initializing NvdCveAnalyzer", ex);
            throw new InitializationException(ex);
        } catch (DatabaseException ex) {
            LOGGER.debug("Database Exception initializing NvdCveAnalyzer", ex);
            throw new InitializationException(ex);
        } catch (ClassNotFoundException ex) {
            LOGGER.debug("Exception initializing NvdCveAnalyzer", ex);
            throw new InitializationException(ex);
        }
    }
}
