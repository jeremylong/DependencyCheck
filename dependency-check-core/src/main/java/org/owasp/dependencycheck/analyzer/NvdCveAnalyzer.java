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

/**
 * NvdCveAnalyzer is a utility class that takes a project dependency and attempts to discern if there is an associated
 * CVEs. It uses the the identifiers found by other analyzers to lookup the CVE data.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NvdCveAnalyzer implements Analyzer {

    /**
     * The maximum number of query results to return.
     */
    static final int MAX_QUERY_RESULTS = 100;
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
     * @throws ClassNotFoundException thrown if the h2 database driver cannot be loaded
     */
    public void open() throws SQLException, IOException, DatabaseException, ClassNotFoundException {
        cveDB = new CveDB();
        cveDB.open();
    }

    /**
     * Closes the data source.
     */
    @Override
    public void close() {
        cveDB.close();
        cveDB = null;
    }

    /**
     * Returns the status of the data source - is the database open.
     *
     * @return true or false.
     */
    public boolean isOpen() {
        return (cveDB != null);
    }

    /**
     * Ensures that the CVE Database is closed.
     *
     * @throws Throwable when a throwable is thrown.
     */
    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        if (isOpen()) {
            close();
        }
    }

    /**
     * Analyzes a dependency and attempts to determine if there are any CPE identifiers for this dependency.
     *
     * @param dependency The Dependency to analyze
     * @param engine The analysis engine
     * @throws AnalysisException is thrown if there is an issue analyzing the dependency
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
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
     * Opens the database used to gather NVD CVE data.
     *
     * @throws Exception is thrown if there is an issue opening the index.
     */
    @Override
    public void initialize() throws Exception {
        this.open();
    }
}
