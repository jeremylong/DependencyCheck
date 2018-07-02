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

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nsp.Advisory;
import org.owasp.dependencycheck.data.nsp.NspSearch;
import org.owasp.dependencycheck.data.nsp.SanitizePackage;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import org.owasp.dependencycheck.analyzer.exception.SearchException;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;

/**
 * Used to analyze Node Package Manager (npm) package.json files via Node
 * Security Platform (nsp).
 *
 * @author Steve Springett
 */
@ThreadSafe
public class NspAnalyzer extends AbstractNpmAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NspAnalyzer.class);

    /**
     * The default URL to the NSP check API.
     */
    public static final String DEFAULT_URL = "https://api.nodesecurity.io/check";
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = NPM_DEPENDENCY_ECOSYSTEM;
    /**
     * The file name to scan.
     */
    private static final String PACKAGE_JSON = "package.json";

    /**
     * Filter that detects files named "package.json".
     */
    private static final FileFilter PACKAGE_JSON_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(PACKAGE_JSON).build();

    /**
     * The NSP Searcher.
     */
    private NspSearch searcher;

    /**
     * Returns the FileFilter
     *
     * @return the FileFilter
     */
    @Override
    protected FileFilter getFileFilter() {
        return PACKAGE_JSON_FILTER;
    }

    /**
     * Initializes the analyzer once before any analysis is performed.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException if there's an error during initialization
     */
    @Override
    public void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        LOGGER.debug("Initializing {}", getName());
        try {
            searcher = new NspSearch(getSettings());
        } catch (MalformedURLException ex) {
            setEnabled(false);
            throw new InitializationException("The configured URL to Node Security Platform is malformed", ex);
        }
        try {
            final Settings settings = engine.getSettings();
            final boolean nodeEnabled = settings.getBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED);
            if (!nodeEnabled) {
                LOGGER.warn("The Node Package Analyzer has been disabled; the resulting report will only "
                        + " contain the known vulnerable dependency - not a bill of materials for the node project.");
            }
        } catch (InvalidSettingException ex) {
            throw new InitializationException("Unable to read configuration settings", ex);
        }
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return "Node Security Platform Analyzer";
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
    }

    /**
     * Returns the key used in the properties file to determine if the analyzer
     * is enabled.
     *
     * @return the enabled property setting key for the analyzer
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_NSP_PACKAGE_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (dependency.getDisplayFileName().equals(dependency.getFileName()))  {
            engine.removeDependency(dependency);
        }
        final File file = dependency.getActualFile();
        if (!file.isFile() || file.length() == 0 || !shouldProcess(file)) {
            return;
        }

        try (JsonReader jsonReader = Json.createReader(FileUtils.openInputStream(file))) {

            // Retrieves the contents of package.json from the Dependency
            final JsonObject packageJson = jsonReader.readObject();

            // Create a sanitized version of the package.json
            final JsonObject sanitizedJson = SanitizePackage.sanitize(packageJson);

            // Create a new 'package' object that acts as a container for the sanitized package.json
            final JsonObjectBuilder builder = Json.createObjectBuilder();
            final JsonObject nspPayload = builder.add("package", sanitizedJson).build();

            // Submits the package payload to the nsp check service
            final List<Advisory> advisories = searcher.submitPackage(nspPayload);

            for (Advisory advisory : advisories) {
                /*
                 * Create a new vulnerability out of the advisory returned by nsp.
                 */
                final Vulnerability vuln = new Vulnerability();
                vuln.setCvssScore(advisory.getCvssScore());
                vuln.setDescription(advisory.getOverview());
                vuln.setName(String.valueOf(advisory.getId()));
                vuln.setSource(Vulnerability.Source.NSP);
                vuln.addReference(
                        "NSP",
                        "Advisory " + advisory.getId() + ": " + advisory.getTitle(),
                        advisory.getAdvisory()
                );

                /*
                 * Create a single vulnerable software object - these do not use CPEs unlike the NVD.
                 */
                final VulnerableSoftware vs = new VulnerableSoftware();
                //TODO consider changing this to available versions on the dependency
                //  - the update is a part of the version, not versions to update to
                //vs.setUpdate(advisory.getPatchedVersions());

                vs.setName(advisory.getModule() + ":" + advisory.getVulnerableVersions());
                vuln.setVulnerableSoftware(new HashSet<>(Arrays.asList(vs)));

                final Dependency existing = findDependency(engine, advisory.getModule(), advisory.getVersion());
                if (existing == null) {
                    final Dependency nodeModule = createDependency(dependency, advisory.getModule(), advisory.getVersion(), "transitive");
                    nodeModule.addVulnerability(vuln);
                    engine.addDependency(nodeModule);
                } else {
                    existing.addVulnerability(vuln);
                }
            }
        } catch (URLConnectionFailureException e) {
            this.setEnabled(false);
            throw new AnalysisException("Failed to connect to the Node Security Project (NspAnalyzer); the analyzer "
                    + "is being disabled and may result in false negatives.", e);
        } catch (IOException e) {
            LOGGER.debug("Error reading dependency or connecting to Node Security Platform - check API", e);
            this.setEnabled(false);
            throw new AnalysisException("Failed to read results from the Node Security Project (NspAnalyzer); "
                    + "the analyzer is being disabled and may result in false negatives.", e);
        } catch (JsonException e) {
            throw new AnalysisException(String.format("Failed to parse %s file from the Node Security Platform "
                    + "(NspAnalyzer).", file.getPath()), e);
        } catch (SearchException ex) {
            LOGGER.error("NspAnalyzer failed on {}", dependency.getActualFilePath());
            throw ex;
        }
    }
}
