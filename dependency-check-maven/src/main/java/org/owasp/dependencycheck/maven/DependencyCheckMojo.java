/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.reporting.MavenReport;
import org.apache.maven.reporting.MavenReportException;
import org.apache.maven.settings.Proxy;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.DependencyBundlingAnalyzer;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.utils.LogUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Maven Plugin that checks project dependencies to see if they have any known published vulnerabilities.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
@Mojo(name = "check", defaultPhase = LifecyclePhase.COMPILE, threadSafe = true, requiresDependencyResolution = ResolutionScope.RUNTIME_PLUS_SYSTEM, requiresOnline = true)
public class DependencyCheckMojo extends ReportAggregationMojo {

    //<editor-fold defaultstate="collapsed" desc="Private fields">
    /**
     * Logger field reference.
     */
    private static final Logger LOGGER = Logger.getLogger(DependencyCheckMojo.class.getName());
    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "mojo.properties";
    /**
     * Name of the logging properties file.
     */
    private static final String LOG_PROPERTIES_FILE = "log.properties";
    /**
     * System specific new line character.
     */
    private static final String NEW_LINE = System.getProperty("line.separator", "\n").intern();
    /**
     * The dependency-check engine used to scan the project.
     */
    private Engine engine = null;
    //</editor-fold>

    // <editor-fold defaultstate="collapsed" desc="Maven bound parameters and components">
    /**
     * The path to the verbose log.
     */
    @Parameter(property = "logfile", defaultValue = "")
    private String logFile = null;
    /**
     * The output directory. This generally maps to "target".
     */
    @Parameter(defaultValue = "${project.build.directory}", required = true)
    private File outputDirectory;
    /**
     * Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11
     * which means since the CVSS scores are 0-10, by default the build will never fail.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "failBuildOnCVSS", defaultValue = "11", required = true)
    private float failBuildOnCVSS = 11;
    /**
     * Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to
     * false. Default is true.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "autoupdate", defaultValue = "true", required = true)
    private boolean autoUpdate = true;
    /**
     * The report format to be generated (HTML, XML, VULN, ALL). This configuration option has no affect if using this
     * within the Site plugin unless the externalReport is set to true. Default is HTML.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "format", defaultValue = "HTML", required = true)
    private String format = "HTML";
    /**
     * The maven settings.
     */
    @Parameter(property = "mavenSettings", defaultValue = "${settings}", required = false)
    private org.apache.maven.settings.Settings mavenSettings;

    /**
     * The maven settings proxy id.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "mavenSettingsProxyId", required = false)
    private String mavenSettingsProxyId;

    /**
     * The Connection Timeout.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "connectionTimeout", defaultValue = "", required = false)
    private String connectionTimeout = null;
    /**
     * The path to the suppression file.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "suppressionFile", defaultValue = "", required = false)
    private String suppressionFile = null;
    /**
     * Flag indicating whether or not to show a summary in the output.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "showSummary", defaultValue = "true", required = false)
    private boolean showSummary = true;

    /**
     * Whether or not the Jar Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "jarAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean jarAnalyzerEnabled = true;

    /**
     * Whether or not the Archive Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "archiveAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean archiveAnalyzerEnabled = true;

    /**
     * Whether or not the .NET Assembly Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "assemblyAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean assemblyAnalyzerEnabled = true;

    /**
     * Whether or not the .NET Nuspec Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nuspecAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean nuspecAnalyzerEnabled = true;

    /**
     * Whether or not the Nexus Analyzer is enabled.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "nexusAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean nexusAnalyzerEnabled = true;
    /**
     * Whether or not the Nexus Analyzer is enabled.
     */
    @Parameter(property = "nexusUrl", defaultValue = "", required = false)
    private String nexusUrl;
    /**
     * Whether or not the configured proxy is used to connect to Nexus.
     */
    @Parameter(property = "nexusUsesProxy", defaultValue = "true", required = false)
    private boolean nexusUsesProxy = true;
    /**
     * The database connection string.
     */
    @Parameter(property = "connectionString", defaultValue = "", required = false)
    private String connectionString;
    /**
     * The database driver name. An example would be org.h2.Driver.
     */
    @Parameter(property = "databaseDriverName", defaultValue = "", required = false)
    private String databaseDriverName;
    /**
     * The path to the database driver if it is not on the class path.
     */
    @Parameter(property = "databaseDriverPath", defaultValue = "", required = false)
    private String databaseDriverPath;
    /**
     * The database user name.
     */
    @Parameter(property = "databaseUser", defaultValue = "", required = false)
    private String databaseUser;
    /**
     * The password to use when connecting to the database.
     */
    @Parameter(property = "databasePassword", defaultValue = "", required = false)
    private String databasePassword;
    /**
     * A comma-separated list of file extensions to add to analysis next to jar, zip, ....
     */
    @Parameter(property = "zipExtensions", required = false)
    private String zipExtensions;
    /**
     * Skip Analysis for Test Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipTestScope", defaultValue = "true", required = false)
    private boolean skipTestScope = true;
    /**
     * Skip Analysis for Runtime Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipRuntimeScope", defaultValue = "false", required = false)
    private boolean skipRuntimeScope = false;
    /**
     * Skip Analysis for Provided Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipProvidedScope", defaultValue = "false", required = false)
    private boolean skipProvidedScope = false;
    /**
     * The data directory, hold DC SQL DB.
     */
    @Parameter(property = "dataDirectory", defaultValue = "", required = false)
    private String dataDirectory;
    /**
     * Data Mirror URL for CVE 1.2.
     */
    @Parameter(property = "cveUrl12Modified", defaultValue = "", required = false)
    private String cveUrl12Modified;
    /**
     * Data Mirror URL for CVE 2.0.
     */
    @Parameter(property = "cveUrl20Modified", defaultValue = "", required = false)
    private String cveUrl20Modified;
    /**
     * Base Data Mirror URL for CVE 1.2.
     */
    @Parameter(property = "cveUrl12Base", defaultValue = "", required = false)
    private String cveUrl12Base;
    /**
     * Data Mirror URL for CVE 2.0.
     */
    @Parameter(property = "cveUrl20Base", defaultValue = "", required = false)
    private String cveUrl20Base;

    /**
     * The path to mono for .NET Assembly analysis on non-windows systems.
     */
    @Parameter(property = "pathToMono", defaultValue = "", required = false)
    private String pathToMono;

    /**
     * The Proxy URL.
     *
     * @deprecated Please use mavenSettings instead
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "proxyUrl", defaultValue = "", required = false)
    @Deprecated
    private String proxyUrl = null;
    /**
     * Sets whether or not the external report format should be used.
     *
     * @deprecated the internal report is no longer supported
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "externalReport")
    @Deprecated
    private String externalReport = null;

    // </editor-fold>
    /**
     * Constructs a new dependency-check-mojo.
     */
    public DependencyCheckMojo() {
        final InputStream in = DependencyCheckMojo.class.getClassLoader().getResourceAsStream(LOG_PROPERTIES_FILE);
        LogUtils.prepareLogger(in, logFile);
    }

    /**
     * Executes the Dependency-Check on the dependent libraries.
     *
     * @return the Engine used to scan the dependencies.
     * @throws DatabaseException thrown if there is an exception connecting to the database
     */
    private Engine executeDependencyCheck() throws DatabaseException {
        return executeDependencyCheck(getProject());
    }

    /**
     * Executes the Dependency-Check on the dependent libraries.
     *
     * @param project the project to run dependency-check on
     * @return the Engine used to scan the dependencies.
     * @throws DatabaseException thrown if there is an exception connecting to the database
     */
    private Engine executeDependencyCheck(MavenProject project) throws DatabaseException {
        final Engine localEngine = initializeEngine();

        final Set<Artifact> artifacts = project.getArtifacts();
        for (Artifact a : artifacts) {
            if (excludeFromScan(a)) {
                continue;
            }
            localEngine.scan(a.getFile().getAbsoluteFile(), new MavenArtifact(a.getGroupId(), a.getArtifactId(), a.getVersion()));
        }
        localEngine.analyzeDependencies();

        return localEngine;
    }

    /**
     * Initializes a new <code>Engine</code> that can be used for scanning.
     *
     * @return a newly instantiated <code>Engine</code>
     * @throws DatabaseException thrown if there is a database exception
     */
    private Engine initializeEngine() throws DatabaseException {
        populateSettings();
        final Engine localEngine = new Engine();
        return localEngine;
    }

    /**
     * Tests is the artifact should be included in the scan (i.e. is the dependency in a scope that is being scanned).
     *
     * @param a the Artifact to test
     * @return <code>true</code> if the artifact is in an excluded scope; otherwise <code>false</code>
     */
    private boolean excludeFromScan(Artifact a) {
        if (skipTestScope && Artifact.SCOPE_TEST.equals(a.getScope())) {
            return true;
        }
        if (skipProvidedScope && Artifact.SCOPE_PROVIDED.equals(a.getScope())) {
            return true;
        }
        if (skipRuntimeScope && !Artifact.SCOPE_RUNTIME.equals(a.getScope())) {
            return true;
        }
        return false;
    }

    //<editor-fold defaultstate="collapsed" desc="Methods to populate global settings">
    /**
     * Takes the properties supplied and updates the dependency-check settings. Additionally, this sets the system
     * properties required to change the proxy url, port, and connection timeout.
     */
    private void populateSettings() {
        Settings.initialize();
        InputStream mojoProperties = null;
        try {
            mojoProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
            Settings.mergeProperties(mojoProperties);
        } catch (IOException ex) {
            LOGGER.log(Level.WARNING, "Unable to load the dependency-check ant task.properties file.");
            LOGGER.log(Level.FINE, null, ex);
        } finally {
            if (mojoProperties != null) {
                try {
                    mojoProperties.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.FINEST, null, ex);
                }
            }
        }

        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);
        if (externalReport != null) {
            LOGGER.warning("The 'externalReport' option was set; this configuration option has been removed. "
                    + "Please update the dependency-check-maven plugin's configuration");
        }

        if (proxyUrl != null && !proxyUrl.isEmpty()) {
            LOGGER.warning("Deprecated configuration detected, proxyUrl will be ignored; use the maven settings " + "to configure the proxy instead");
        }
        final Proxy proxy = getMavenProxy();
        if (proxy != null) {
            Settings.setString(Settings.KEYS.PROXY_SERVER, proxy.getHost());
            Settings.setString(Settings.KEYS.PROXY_PORT, Integer.toString(proxy.getPort()));
            final String userName = proxy.getUsername();
            final String password = proxy.getPassword();
            if (userName != null) {
                Settings.setString(Settings.KEYS.PROXY_USERNAME, userName);
            }
            if (password != null) {
                Settings.setString(Settings.KEYS.PROXY_PASSWORD, password);
            }

        }

        if (connectionTimeout != null && !connectionTimeout.isEmpty()) {
            Settings.setString(Settings.KEYS.CONNECTION_TIMEOUT, connectionTimeout);
        }
        if (suppressionFile != null && !suppressionFile.isEmpty()) {
            Settings.setString(Settings.KEYS.SUPPRESSION_FILE, suppressionFile);
        }

        //File Type Analyzer Settings
        //JAR ANALYZER
        Settings.setBoolean(Settings.KEYS.ANALYZER_JAR_ENABLED, jarAnalyzerEnabled);
        //NUSPEC ANALYZER
        Settings.setBoolean(Settings.KEYS.ANALYZER_NUSPEC_ENABLED, nuspecAnalyzerEnabled);
        //NEXUS ANALYZER
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, nexusAnalyzerEnabled);
        if (nexusUrl != null && !nexusUrl.isEmpty()) {
            Settings.setString(Settings.KEYS.ANALYZER_NEXUS_URL, nexusUrl);
        }
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_PROXY, nexusUsesProxy);
        //ARCHIVE ANALYZER
        Settings.setBoolean(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, archiveAnalyzerEnabled);
        if (zipExtensions != null && !zipExtensions.isEmpty()) {
            Settings.setString(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS, zipExtensions);
        }
        //ASSEMBLY ANALYZER
        Settings.setBoolean(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, assemblyAnalyzerEnabled);
        if (pathToMono != null && !pathToMono.isEmpty()) {
            Settings.setString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, pathToMono);
        }

        //Database configuration
        if (databaseDriverName != null && !databaseDriverName.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_DRIVER_NAME, databaseDriverName);
        }
        if (databaseDriverPath != null && !databaseDriverPath.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_DRIVER_PATH, databaseDriverPath);
        }
        if (connectionString != null && !connectionString.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_CONNECTION_STRING, connectionString);
        }
        if (databaseUser != null && !databaseUser.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_USER, databaseUser);
        }
        if (databasePassword != null && !databasePassword.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_PASSWORD, databasePassword);
        }
        // Data Directory
        if (dataDirectory != null && !dataDirectory.isEmpty()) {
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        }

        // Scope Exclusion
        Settings.setBoolean(Settings.KEYS.SKIP_TEST_SCOPE, skipTestScope);
        Settings.setBoolean(Settings.KEYS.SKIP_RUNTIME_SCOPE, skipRuntimeScope);
        Settings.setBoolean(Settings.KEYS.SKIP_PROVIDED_SCOPE, skipProvidedScope);

        // CVE Data Mirroring
        if (cveUrl12Modified != null && !cveUrl12Modified.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_MODIFIED_12_URL, cveUrl12Modified);
        }
        if (cveUrl20Modified != null && !cveUrl20Modified.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_MODIFIED_20_URL, cveUrl20Modified);
        }
        if (cveUrl12Base != null && !cveUrl12Base.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_SCHEMA_1_2, cveUrl12Base);
        }
        if (cveUrl20Base != null && !cveUrl20Base.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_SCHEMA_2_0, cveUrl20Base);
        }
    }

    /**
     * Returns the maven proxy.
     *
     * @return the maven proxy
     */
    private Proxy getMavenProxy() {
        if (mavenSettings != null) {
            final List<Proxy> proxies = mavenSettings.getProxies();
            if (proxies != null && proxies.size() > 0) {
                if (mavenSettingsProxyId != null) {
                    for (Proxy proxy : proxies) {
                        if (mavenSettingsProxyId.equalsIgnoreCase(proxy.getId())) {
                            return proxy;
                        }
                    }
                } else if (proxies.size() == 1) {
                    return proxies.get(0);
                } else {
                    LOGGER.warning("Multiple proxy defentiions exist in the Maven settings. In the dependency-check "
                            + "configuration set the maveSettingsProxyId so that the correct proxy will be used.");
                    throw new IllegalStateException("Ambiguous proxy definition");
                }
            }
        }
        return null;
    }

    //</editor-fold>

    /**
     * Executes the dependency-check and generates the report.
     *
     * @throws MojoExecutionException if a maven exception occurs
     * @throws MojoFailureException thrown if a CVSS score is found that is higher then the configured level
     */
    @Override
    protected void performExecute() throws MojoExecutionException, MojoFailureException {
        try {
            engine = executeDependencyCheck();
            ReportingUtil.generateExternalReports(engine, outputDirectory, getProject().getName(), format);
            if (this.showSummary) {
                showSummary(engine.getDependencies());
            }
            if (this.failBuildOnCVSS <= 10) {
                checkForFailure(engine.getDependencies());
            }
        } catch (DatabaseException ex) {
            LOGGER.log(Level.SEVERE, "Unable to connect to the dependency-check database; analysis has stopped");
            LOGGER.log(Level.FINE, "", ex);
        }
    }

    @Override
    protected void postExecute() throws MojoExecutionException, MojoFailureException {
        try {
            super.postExecute();
        } finally {
            cleanupEngine();
        }
    }

    @Override
    protected void postGenerate() throws MavenReportException {
        try {
            super.postGenerate();
        } finally {
            cleanupEngine();
        }
    }

    /**
     * Calls <code>engine.cleanup()</code> to release resources.
     */
    private void cleanupEngine() {
        if (engine != null) {
            engine.cleanup();
            engine = null;
        }
        Settings.cleanup(true);
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    @Override
    protected void executeNonAggregateReport(Locale locale) throws MavenReportException {

        final List<Dependency> deps = readDataFile();
        if (deps != null) {
            try {
                engine = initializeEngine();
                engine.getDependencies().addAll(deps);
            } catch (DatabaseException ex) {
                final String msg = String.format("An unrecoverable exception with the dependency-check initialization occured while scanning %s", getProject()
                        .getName());
                throw new MavenReportException(msg, ex);
            }
        } else {
            try {
                engine = executeDependencyCheck();
            } catch (DatabaseException ex) {
                final String msg = String.format("An unrecoverable exception with the dependency-check scan occured while scanning %s", getProject().getName());
                throw new MavenReportException(msg, ex);
            }
        }
        ReportingUtil.generateExternalReports(engine, getReportOutputDirectory(), getProject().getName(), format);
    }

    @Override
    protected void executeAggregateReport(MavenProject project, Locale locale) throws MavenReportException {
        List<Dependency> deps = readDataFile(project);
        if (deps != null) {
            try {
                engine = initializeEngine();
                engine.getDependencies().addAll(deps);
            } catch (DatabaseException ex) {
                final String msg = String.format("An unrecoverable exception with the dependency-check initialization occured while scanning %s",
                        project.getName());
                throw new MavenReportException(msg, ex);
            }
        } else {
            try {
                engine = executeDependencyCheck(project);
            } catch (DatabaseException ex) {
                final String msg = String.format("An unrecoverable exception with the dependency-check scan occured while scanning %s", project.getName());
                throw new MavenReportException(msg, ex);
            }
        }
        for (MavenProject child : getAllChildren(project)) {
            deps = readDataFile(child);
            if (deps == null) {
                final String msg = String.format("Unable to include information on %s in the dependency-check aggregate report", child.getName());
                LOGGER.severe(msg);
            } else {
                engine.getDependencies().addAll(deps);
            }
        }
        final DependencyBundlingAnalyzer bundler = new DependencyBundlingAnalyzer();
        try {
            bundler.analyze(null, engine);
        } catch (AnalysisException ex) {
            LOGGER.log(Level.WARNING, "An error occured grouping the dependencies; duplicate entries may exist in the report", ex);
            LOGGER.log(Level.FINE, "Bundling Exception", ex);
        }
        final File outputDir = getReportOutputDirectory(project);
        if (outputDir != null) {
            ReportingUtil.generateExternalReports(engine, outputDir, project.getName(), format);
        }
    }

    // <editor-fold defaultstate="collapsed" desc="Mojo interface/abstract required setter/getter methods">
    /**
     * Returns the output name.
     *
     * @return the output name
     */
    public String getOutputName() {
        if ("HTML".equalsIgnoreCase(this.format) || "ALL".equalsIgnoreCase(this.format)) {
            return "dependency-check-report";
        } else if ("XML".equalsIgnoreCase(this.format)) {
            return "dependency-check-report.xml#";
        } else if ("VULN".equalsIgnoreCase(this.format)) {
            return "dependency-check-vulnerability";
        } else {
            LOGGER.log(Level.WARNING, "Unknown report format used during site generation.");
            return "dependency-check-report";
        }
    }

    /**
     * Returns the category name.
     *
     * @return the category name
     */
    public String getCategoryName() {
        return MavenReport.CATEGORY_PROJECT_REPORTS;
    }

    /**
     * Returns the report name.
     *
     * @param locale the location
     * @return the report name
     */
    public String getName(Locale locale) {
        return "dependency-check";
    }

    /**
     * Gets the description of the Dependency-Check report to be displayed in the Maven Generated Reports page.
     *
     * @param locale The Locale to get the description for
     * @return the description
     */
    public String getDescription(Locale locale) {
        return "A report providing details on any published " + "vulnerabilities within project dependencies. This report is a best effort but may contain "
                + "false positives and false negatives.";
    }

    /**
     * Returns whether or not a report can be generated.
     *
     * @return <code>true</code> if a report can be generated; otherwise <code>false</code>
     */
    public boolean canGenerateReport() {
        if (canGenerateAggregateReport() || (isAggregate() && isMultiModule())) {
            return true;
        }
        if (canGenerateNonAggregateReport()) {
            return true;
        } else {
            final String msg;
            if (getProject().getArtifacts().size() > 0) {
                msg = "No project dependencies exist in the included scope - dependency-check:check is unable to generate a report.";
            } else {
                msg = "No project dependencies exist - dependency-check:check is unable to generate a report.";
            }
            LOGGER.warning(msg);
        }

        return false;
    }

    /**
     * Returns whether or not a non-aggregate report can be generated.
     *
     * @return <code>true</code> if a non-aggregate report can be generated; otherwise <code>false</code>
     */
    @Override
    protected boolean canGenerateNonAggregateReport() {
        boolean ability = false;
        for (Artifact a : getProject().getArtifacts()) {
            if (!excludeFromScan(a)) {
                ability = true;
                break;
            }
        }
        return ability;
    }

    /**
     * Returns whether or not an aggregate report can be generated.
     *
     * @return <code>true</code> if an aggregate report can be generated; otherwise <code>false</code>
     */
    @Override
    protected boolean canGenerateAggregateReport() {
        return isAggregate() && isLastProject();
    }

    // </editor-fold>

    //<editor-fold defaultstate="collapsed" desc="Methods to fail build or show summary">
    /**
     * Checks to see if a vulnerability has been identified with a CVSS score that is above the threshold set in the
     * configuration.
     *
     * @param dependencies the list of dependency objects
     * @throws MojoFailureException thrown if a CVSS score is found that is higher then the threshold set
     */
    private void checkForFailure(List<Dependency> dependencies) throws MojoFailureException {
        final StringBuilder ids = new StringBuilder();
        for (Dependency d : dependencies) {
            boolean addName = true;
            for (Vulnerability v : d.getVulnerabilities()) {
                if (v.getCvssScore() >= failBuildOnCVSS) {
                    if (addName) {
                        addName = false;
                        ids.append(NEW_LINE).append(d.getFileName()).append(": ");
                        ids.append(v.getName());
                    } else {
                        ids.append(", ").append(v.getName());
                    }
                }
            }
        }
        if (ids.length() > 0) {
            final String msg = String.format("%n%nDependency-Check Failure:%n"
                    + "One or more dependencies were identified with vulnerabilities that have a CVSS score greater then '%.1f': %s%n"
                    + "See the dependency-check report for more details.%n%n", failBuildOnCVSS, ids.toString());
            throw new MojoFailureException(msg);
        }
    }

    /**
     * Generates a warning message listing a summary of dependencies and their associated CPE and CVE entries.
     *
     * @param dependencies a list of dependency objects
     */
    private void showSummary(List<Dependency> dependencies) {
        final StringBuilder summary = new StringBuilder();
        for (Dependency d : dependencies) {
            boolean firstEntry = true;
            final StringBuilder ids = new StringBuilder();
            for (Vulnerability v : d.getVulnerabilities()) {
                if (firstEntry) {
                    firstEntry = false;
                } else {
                    ids.append(", ");
                }
                ids.append(v.getName());
            }
            if (ids.length() > 0) {
                summary.append(d.getFileName()).append(" (");
                firstEntry = true;
                for (Identifier id : d.getIdentifiers()) {
                    if (firstEntry) {
                        firstEntry = false;
                    } else {
                        summary.append(", ");
                    }
                    summary.append(id.getValue());
                }
                summary.append(") : ").append(ids).append(NEW_LINE);
            }
        }
        if (summary.length() > 0) {
            final String msg = String.format("%n%n" + "One or more dependencies were identified with known vulnerabilities:%n%n%s"
                    + "%n%nSee the dependency-check report for more details.%n%n", summary.toString());
            LOGGER.log(Level.WARNING, msg);
        }
    }

    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="Methods to read/write the serialized data file">
    /**
     * Writes the scan data to disk. This is used to serialize the scan data between the "check" and "aggregate" phase.
     *
     * @return the File object referencing the data file that was written
     */
    @Override
    protected File writeDataFile() {
        File file = null;
        if (engine != null && getProject().getContextValue(this.getDataFileContextKey()) == null) {
            file = new File(getProject().getBuild().getDirectory(), getDataFileName());
            OutputStream os = null;
            OutputStream bos = null;
            ObjectOutputStream out = null;
            try {
                os = new FileOutputStream(file);
                bos = new BufferedOutputStream(os);
                out = new ObjectOutputStream(bos);
                out.writeObject(engine.getDependencies());
                out.flush();

                //call reset to prevent resource leaks per
                //https://www.securecoding.cert.org/confluence/display/java/SER10-J.+Avoid+memory+and+resource+leaks+during+serialization
                out.reset();

            } catch (IOException ex) {
                LOGGER.log(Level.WARNING, "Unable to create data file used for report aggregation; "
                        + "if report aggregation is being used the results may be incomplete.");
                LOGGER.log(Level.FINE, ex.getMessage(), ex);
            } finally {
                if (out != null) {
                    try {
                        out.close();
                    } catch (IOException ex) {
                        LOGGER.log(Level.FINEST, "ignore", ex);
                    }
                }
                if (bos != null) {
                    try {
                        bos.close();
                    } catch (IOException ex) {
                        LOGGER.log(Level.FINEST, "ignore", ex);
                    }
                }
                if (os != null) {
                    try {
                        os.close();
                    } catch (IOException ex) {
                        LOGGER.log(Level.FINEST, "ignore", ex);
                    }
                }
            }
        }
        return file;
    }

    /**
     * Reads the serialized scan data from disk. This is used to serialize the scan data between the "check" and
     * "aggregate" phase.
     *
     * @return a <code>Engine</code> object populated with dependencies if the serialized data file exists; otherwise
     * <code>null</code> is returned
     */
    protected List<Dependency> readDataFile() {
        return readDataFile(getProject());
    }

    /**
     * Reads the serialized scan data from disk. This is used to serialize the scan data between the "check" and
     * "aggregate" phase.
     *
     * @param project the Maven project to read the data file from
     * @return a <code>Engine</code> object populated with dependencies if the serialized data file exists; otherwise
     * <code>null</code> is returned
     */
    protected List<Dependency> readDataFile(MavenProject project) {
        final Object oPath = project.getContextValue(this.getDataFileContextKey());
        if (oPath == null) {
            return null;
        }
        List<Dependency> ret = null;
        final String path = (String) oPath;
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(new FileInputStream(path));
            ret = (List<Dependency>) ois.readObject();
        } catch (FileNotFoundException ex) {
            //TODO fix logging
            LOGGER.log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        } finally {
            if (ois != null) {
                try {
                    ois.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.SEVERE, null, ex);
                }
            }
        }
        return ret;
    }
    //</editor-fold>
}
