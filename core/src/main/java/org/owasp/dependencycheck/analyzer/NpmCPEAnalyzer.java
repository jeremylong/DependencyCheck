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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.queryparser.classic.ParseException;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.cpe.IndexException;
import org.owasp.dependencycheck.data.cpe.NpmCpeMemoryIndex;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * NpmCPEAnalyzer takes a project dependency and attempts to discern if there is
 * an associated CPE. Unlike the CPEAnalyzer, the NpmCPEAnalyzer only includes
 * product and vendor associates known to be related to node from the NVD data
 * set. It uses the evidence contained within the dependency to search the
 * Lucene index.
 *
 * @author Jeremy Long
 */
@ThreadSafe
@Experimental
public class NpmCPEAnalyzer extends CPEAnalyzer {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CPEAnalyzer.class);

    /**
     * Returns the analysis phase that this analyzer should run in.
     *
     * @return the analysis phase that this analyzer should run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        //TODO this is a hack because we use the same singleton CPE Index as the CPE Analyzer
        // thus to filter to just node products we can't run in the same phase.
        // possibly extenend the CPE Index to include an ecosystem and use that
        // as a filter for node..
        return AnalysisPhase.PRE_IDENTIFIER_ANALYSIS;
    }

    /**
     * Returns the name of this analyzer.
     *
     * @return the name of this analyzer.
     */
    @Override
    public String getName() {
        return "NPM CPE Analyzer";
    }

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NPM_CPE_ENABLED;
    }

    /**
     * Opens the data source.
     *
     * @param cve a reference to the NVD CVE database
     * @throws IOException when the Lucene directory to be queried does not
     * exist or is corrupt.
     * @throws DatabaseException when the database throws an exception. This
     * usually occurs when the database is in use by another process.
     */
    @Override
    public void open(CveDB cve) throws IOException, DatabaseException {
        setCveDB(cve);
        setMemoryIndex(NpmCpeMemoryIndex.getInstance());
        try {
            final long creationStart = System.currentTimeMillis();
            getMemoryIndex().open(cve.getVendorProductListForNode(), this.getSettings());
            final long creationSeconds = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() - creationStart);
            LOGGER.info("Created CPE Index ({} seconds)", creationSeconds);
        } catch (IndexException ex) {
            LOGGER.debug("IndexException", ex);
            throw new DatabaseException(ex);
        }
    }

    /**
     * Analyzes a dependency and attempts to determine if there are any CPE
     * identifiers for this dependency.
     *
     * @param dependency The Dependency to analyze.
     * @param engine The analysis engine
     * @throws AnalysisException is thrown if there is an issue analyzing the
     * dependency.
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (!"npm".equals(dependency.getEcosystem())) {
            return;
        }
        try {
            determineCPE(dependency);
        } catch (CorruptIndexException ex) {
            throw new AnalysisException("CPE Index is corrupt.", ex);
        } catch (IOException ex) {
            throw new AnalysisException("Failure opening the CPE Index.", ex);
        } catch (ParseException ex) {
            throw new AnalysisException("Unable to parse the generated Lucene query for this dependency.", ex);
        }
    }
}
