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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NodeAuditSearch;
import org.owasp.dependencycheck.data.nodeaudit.SanitizePackage;
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
import javax.json.JsonReader;
import org.owasp.dependencycheck.analyzer.exception.SearchException;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

/**
 * Used to analyze Node Package Manager (npm) package-lock.json and
 * npm-shrinkwrap.json files via NPM Audit API.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class NodeAuditAnalyzer extends AbstractNpmAnalyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NodeAuditAnalyzer.class);
    /**
     * The default URL to the NPM Audit API.
     */
    public static final String DEFAULT_URL = "https://registry.npmjs.org/-/npm/v1/security/audits";
    /**
     * A descriptor for the type of dependencies processed or added by this
     * analyzer.
     */
    public static final String DEPENDENCY_ECOSYSTEM = NPM_DEPENDENCY_ECOSYSTEM;
    /**
     * The file name to scan.
     */
    public static final String PACKAGE_LOCK_JSON = "package-lock.json";
    /**
     * The file name to scan.
     */
    public static final String SHRINKWRAP_JSON = "npm-shrinkwrap.json";

    /**
     * Filter that detects files named "package-lock.json or
     * npm-shrinkwrap.json".
     */
    private static final FileFilter PACKAGE_JSON_FILTER = FileFilterBuilder.newInstance()
            .addFilenames(PACKAGE_LOCK_JSON, SHRINKWRAP_JSON).build();

    /**
     * The Node Audit Searcher.
     */
    private NodeAuditSearch searcher;

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
            searcher = new NodeAuditSearch(getSettings());
        } catch (MalformedURLException ex) {
            setEnabled(false);
            throw new InitializationException("The configured URL to NPM Audit API is malformed", ex);
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
        return "Node Audit Analyzer";
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
        return Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (dependency.getDisplayFileName().equals(dependency.getFileName())) {
            engine.removeDependency(dependency);
        }
        final File file = dependency.getActualFile();
        if (!file.isFile() || file.length() == 0 || !shouldProcess(file)) {
            return;
        }

        try (JsonReader jsonReader = Json.createReader(FileUtils.openInputStream(file))) {

            // Retrieves the contents of package-lock.json from the Dependency
            final JsonObject packageJson = jsonReader.readObject();

            final String projectName = packageJson.getString("name", "");
            final String projectVersion = packageJson.getString("version", "");
            if (!projectName.isEmpty()) {
                dependency.setName(projectName);
            }
            if (!projectVersion.isEmpty()) {
                dependency.setVersion(projectVersion);
            }

            // Modify the payload to meet the NPM Audit API requirements
            final JsonObject payload = SanitizePackage.sanitize(packageJson);

            // Submits the package payload to the nsp check service
            final List<Advisory> advisories = searcher.submitPackage(payload);

            for (Advisory advisory : advisories) {
                /*
                 * Create a new vulnerability out of the advisory returned by nsp.
                 */
                final Vulnerability vuln = new Vulnerability();
                vuln.setDescription(advisory.getOverview());
                vuln.setName(String.valueOf(advisory.getId()));
                vuln.setUnscoredSeverity(advisory.getSeverity());
                vuln.setSource(Vulnerability.Source.NPM);
                vuln.addReference(
                        "Advisory " + advisory.getId() + ": " + advisory.getTitle(),
                        advisory.getReferences(),
                        null
                );

                /*
                 * Create a single vulnerable software object - these do not use CPEs unlike the NVD.
                 */
                final VulnerableSoftwareBuilder builder = new VulnerableSoftwareBuilder();
                //< 3.1.3  || >= 4.0.0 <4.1.1
                builder.part(Part.APPLICATION).product(advisory.getModuleName().replace(" ", "_"))
                        .version(advisory.getVulnerableVersions().replace(" ", ""));
                final VulnerableSoftware vs = builder.build();
                vuln.setVulnerableSoftware(new HashSet<>(Arrays.asList(vs)));

                final Dependency existing = findDependency(engine, advisory.getModuleName(), advisory.getVersion());
                if (existing == null) {
                    final Dependency nodeModule = createDependency(dependency, advisory.getModuleName(), advisory.getVersion(), "transitive");
                    nodeModule.addVulnerability(vuln);
                    engine.addDependency(nodeModule);
                } else {
                    existing.addVulnerability(vuln);
                }
            }
        } catch (URLConnectionFailureException e) {
            this.setEnabled(false);
            throw new AnalysisException("Failed to connect to the NPM Audit API (NodeAuditAnalyzer); the analyzer "
                    + "is being disabled and may result in false negatives.", e);
        } catch (IOException e) {
            LOGGER.debug("Error reading dependency or connecting to NPM Audit API", e);
            this.setEnabled(false);
            throw new AnalysisException("Failed to read results from the NPM Audit API (NodeAuditAnalyzer); "
                    + "the analyzer is being disabled and may result in false negatives.", e);
        } catch (JsonException e) {
            throw new AnalysisException(String.format("Failed to parse %s file from the NPM Audit API "
                    + "(NodeAuditAnalyzer).", file.getPath()), e);
        } catch (SearchException ex) {
            LOGGER.error("NodeAuditAnalyzer failed on {}", dependency.getActualFilePath());
            throw ex;
        } catch (CpeValidationException ex) {
            throw new UnexpectedAnalysisException(ex);
        }
    }
}
