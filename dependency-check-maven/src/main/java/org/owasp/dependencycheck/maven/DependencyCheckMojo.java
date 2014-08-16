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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.doxia.sink.SinkFactory;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.reporting.MavenReport;
import org.apache.maven.reporting.MavenReportException;
import org.apache.maven.settings.Proxy;
import org.owasp.dependencycheck.Engine;
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
@Mojo(name = "check", defaultPhase = LifecyclePhase.COMPILE, threadSafe = true,
        requiresDependencyResolution = ResolutionScope.RUNTIME_PLUS_SYSTEM,
        requiresOnline = true)
public class DependencyCheckMojo extends ReportAggregationMojo {

    /**
     * Logger field reference.
     */
    private static final Logger logger = Logger.getLogger(DependencyCheckMojo.class.getName());

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

    // <editor-fold defaultstate="collapsed" desc="Maven bound parameters and components">
    /**
     * The Maven Project Object.
     */
    @Component
    private MavenProject project;
    /**
     * The path to the verbose log.
     */
    @Parameter(property = "logfile", defaultValue = "")
    private String logFile;
    /**
     * Specifies the destination directory for the generated Dependency-Check report. This generally maps to
     * "target/site".
     */
    @Parameter(property = "reportOutputDirectory", defaultValue = "${project.reporting.outputDirectory}", required = true)
    private File reportOutputDirectory;
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
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "format", defaultValue = "HTML", required = true)
    private String format = "HTML";
    /**
     * Sets whether or not the external report format should be used.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "externalReport", defaultValue = "false", required = true)
    private boolean externalReport = false;

    /**
     * The maven settings.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "mavenSettings", defaultValue = "${settings}", required = false)
    private org.apache.maven.settings.Settings mavenSettings;

    /**
     * The maven settings proxy id.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "mavenSettingsProxyId", required = false)
    private String mavenSettingsProxyId;

    /**
     * The Connection Timeout.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "connectionTimeout", defaultValue = "", required = false)
    private String connectionTimeout = null;
    /**
     * The path to the suppression file.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "suppressionFile", defaultValue = "", required = false)
    private String suppressionFile = null;
    /**
     * Flag indicating whether or not to show a summary in the output.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "showSummary", defaultValue = "true", required = false)
    private boolean showSummary = true;

    /**
     * Whether or not the Jar Analyzer is enabled.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "jarAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean jarAnalyzerEnabled = true;

    /**
     * Whether or not the Archive Analyzer is enabled.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "archiveAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean archiveAnalyzerEnabled = true;

    /**
     * Whether or not the .NET Assembly Analyzer is enabled.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "assemblyAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean assemblyAnalyzerEnabled = true;

    /**
     * Whether or not the .NET Nuspec Analyzer is enabled.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "nuspecAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean nuspecAnalyzerEnabled = true;

    /**
     * Whether or not the Nexus Analyzer is enabled.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "nexusAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean nexusAnalyzerEnabled = true;
    /**
     * Whether or not the Nexus Analyzer is enabled.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "nexusUrl", defaultValue = "", required = false)
    private String nexusUrl;
    /**
     * Whether or not the configured proxy is used to connect to Nexus.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "nexusUsesProxy", defaultValue = "true", required = false)
    private boolean nexusUsesProxy = true;
    /**
     * The database connection string.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "connectionString", defaultValue = "", required = false)
    private String connectionString;
    /**
     * The database driver name. An example would be org.h2.Driver.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "databaseDriverName", defaultValue = "", required = false)
    private String databaseDriverName;
    /**
     * The path to the database driver if it is not on the class path.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "databaseDriverPath", defaultValue = "", required = false)
    private String databaseDriverPath;
    /**
     * The database user name.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "databaseUser", defaultValue = "", required = false)
    private String databaseUser;
    /**
     * The password to use when connecting to the database.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
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
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "proxyUrl", defaultValue = "", required = false)
    @Deprecated
    private String proxyUrl = null;

    // </editor-fold>
    /**
     * Executes the Dependency-Check on the dependent libraries.
     *
     * @return the Engine used to scan the dependencies.
     * @throws DatabaseException thrown if there is an exception connecting to the database
     */
    private Engine executeDependencyCheck() throws DatabaseException {

        final InputStream in = DependencyCheckMojo.class.getClassLoader().getResourceAsStream(LOG_PROPERTIES_FILE);
        LogUtils.prepareLogger(in, logFile);

        populateSettings();
        final Engine engine = new Engine();

        final Set<Artifact> artifacts = project.getArtifacts();
        for (Artifact a : artifacts) {
            if (skipTestScope && Artifact.SCOPE_TEST.equals(a.getScope())) {
                continue;
            }

            if (skipProvidedScope && Artifact.SCOPE_PROVIDED.equals(a.getScope())) {
                continue;
            }

            if (skipRuntimeScope && !Artifact.SCOPE_RUNTIME.equals(a.getScope())) {
                continue;
            }

            engine.scan(a.getFile().getAbsolutePath());
        }
        engine.analyzeDependencies();

        return engine;
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
                    logger.warning("Multiple proxy defentiions exist in the Maven settings. In the dependency-check "
                            + "configuration set the maveSettingsProxyId so that the correct proxy will be used.");
                    throw new IllegalStateException("Ambiguous proxy definition");
                }
            }
        }
        return null;
    }

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
            logger.log(Level.WARNING, "Unable to load the dependency-check ant task.properties file.");
            logger.log(Level.FINE, null, ex);
        } finally {
            if (mojoProperties != null) {
                try {
                    mojoProperties.close();
                } catch (IOException ex) {
                    logger.log(Level.FINEST, null, ex);
                }
            }
        }

        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);

        if (proxyUrl != null && !proxyUrl.isEmpty()) {
            logger.warning("Deprecated configuration detected, proxyUrl will be ignored; use the maven settings to configure the proxy instead");
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
     * Executes the dependency-check and generates the report.
     *
     * @throws MojoExecutionException if a maven exception occurs
     * @throws MojoFailureException thrown if a CVSS score is found that is higher then the configured level
     */
    @Override
    protected void performExecute() throws MojoExecutionException, MojoFailureException {
        try {
            engine = executeDependencyCheck();
            ReportingUtil.generateExternalReports(engine, outputDirectory, project.getName(), format);
            if (this.showSummary) {
                showSummary(engine.getDependencies());
            }
            if (this.failBuildOnCVSS <= 10) {
                checkForFailure(engine.getDependencies());
            }
        } catch (DatabaseException ex) {
            logger.log(Level.SEVERE,
                    "Unable to connect to the dependency-check database; analysis has stopped");
            logger.log(Level.FINE, "", ex);
        }
    }

    @Override
    protected void postExecute() throws MojoExecutionException, MojoFailureException {
        super.postExecute();
        Settings.cleanup(true);
        if (engine != null) {
            engine.cleanup();
            engine = null;
        }
    }

    @Override
    protected void postGenerate() throws MavenReportException {
        super.postGenerate();
        Settings.cleanup(true);
        if (engine != null) {
            engine.cleanup();
            engine = null;
        }
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param sinkFactory the sink factory
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    @Override
    protected void executeNonAggregateReport(Sink sink, SinkFactory sinkFactory, Locale locale) throws MavenReportException {
        try {
            //TODO figure out if the serialized data is present from THIS build and use it instead?
            engine = executeDependencyCheck();
            if (this.externalReport) {
                ReportingUtil.generateExternalReports(engine, reportOutputDirectory, project.getName(), format);
            } else {
                ReportingUtil.generateMavenSiteReport(engine, sink, project.getName());
            }
        } catch (DatabaseException ex) {
            logger.log(Level.SEVERE,
                    "Unable to connect to the dependency-check database; analysis has stopped");
            logger.log(Level.FINE, "", ex);
        }
    }

    // <editor-fold defaultstate="collapsed" desc="required setter/getter methods">
    /**
     * Returns the output name.
     *
     * @return the output name
     */
    public String getOutputName() {
        if ("HTML".equalsIgnoreCase(this.format)
                || "ALL".equalsIgnoreCase(this.format)) {
            return "dependency-check-report";
        } else if ("XML".equalsIgnoreCase(this.format)) {
            return "dependency-check-report.xml#";
        } else if ("VULN".equalsIgnoreCase(this.format)) {
            return "dependency-check-vulnerability";
        } else {
            logger.log(Level.WARNING, "Unknown report format used during site generation.");
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
     * Sets the Reporting output directory.
     *
     * @param directory the output directory
     */
    public void setReportOutputDirectory(File directory) {
        reportOutputDirectory = directory;
    }

    /**
     * Returns the output directory.
     *
     * @return the output directory
     */
    public File getReportOutputDirectory() {
        return reportOutputDirectory;
    }

    /**
     * Gets the description of the Dependency-Check report to be displayed in the Maven Generated Reports page.
     *
     * @param locale The Locale to get the description for
     * @return the description
     */
    public String getDescription(Locale locale) {
        return "A report providing details on any published "
                + "vulnerabilities within project dependencies. This report is a best effort but may contain "
                + "false positives and false negatives.";
    }

    /**
     * Returns whether this is an external report.
     *
     * @return true or false;
     */
    public boolean isExternalReport() {
        return externalReport;
    }

    /**
     * Returns whether or not the plugin can generate a report.
     *
     * @return <code>true</code> if a report can be generated; otherwise <code>false</code>
     */
    public boolean canGenerateReport() {
        return canGenerateNonAggregateReport() || canGenerateAggregateReport();
    }
    // </editor-fold>

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
            final String msg = String.format("%n%n"
                    + "One or more dependencies were identified with known vulnerabilities:%n%n%s"
                    + "%n%nSee the dependency-check report for more details.%n%n", summary.toString());
            logger.log(Level.WARNING, msg);
        }
    }

    @Override
    protected void executeAggregateReport(Sink sink, SinkFactory sinkFactory, Locale locale) throws MavenReportException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected boolean canGenerateNonAggregateReport() {
        return true;
    }

    @Override
    protected boolean canGenerateAggregateReport() {
        return isAggregate() && isLastProject();
    }

    @Override
    protected String getDataFileName() {
        return "dependency-check.ser";
    }

    @Override
    protected void writeDataFile() {
        if (engine != null) {
            File file = new File(project.getBuild().getDirectory(), getDataFileName());
            try {
                OutputStream os = new FileOutputStream(file);
                OutputStream bos = new BufferedOutputStream(os);
                ObjectOutput out = new ObjectOutputStream(bos);
                try {
                    out.writeObject(engine);
                    out.flush();
                } finally {
                    out.close();
                }
                project.setContextValue("dependency-check-path", file.getAbsolutePath());
            } catch (IOException ex) {
                logger.log(Level.WARNING, "Unable to create data file used for report aggregation; "
                        + "if report aggregation is being used the results may be incomplete.");
                logger.log(Level.FINE, ex.getMessage(), ex);
            }
        }
    }
}
