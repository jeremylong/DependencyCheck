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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.reporting.MavenReport;
import org.apache.maven.reporting.MavenReportException;
import org.apache.maven.settings.Proxy;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.LogUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public abstract class BaseDependencyCheckMojo extends AbstractMojo implements MavenReport {

    //<editor-fold defaultstate="collapsed" desc="Private fields">
    /**
     * Logger field reference.
     */
    private static final Logger LOGGER = Logger.getLogger(BaseDependencyCheckMojo.class.getName());
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
     * Sets whether or not the external report format should be used.
     */
    @Parameter(property = "metaFileName", defaultValue = "dependency-check.ser", required = true)
    private String dataFileName;

    //</editor-fold>
    // <editor-fold defaultstate="collapsed" desc="Maven bound parameters and components">
    /**
     * The Maven Project Object.
     */
    @Component
    private MavenProject project;
    /**
     * List of Maven project of the current build
     */
    @Parameter(readonly = true, required = true, property = "reactorProjects")
    private List<MavenProject> reactorProjects;
    /**
     * The path to the verbose log.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "logFile", defaultValue = "")
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
     * Generate aggregate reports in multi-module projects.
     *
     * @deprecated use the aggregate goal instead
     */
    @Parameter(property = "aggregate", defaultValue = "false")
    @Deprecated
    private boolean aggregate;
    /**
     * The report format to be generated (HTML, XML, VULN, ALL). This configuration option has no affect if using this
     * within the Site plug-in unless the externalReport is set to true. Default is HTML.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "format", defaultValue = "HTML", required = true)
    private String format = "HTML";
    /**
     * The Maven settings.
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

    /**
     * Specifies the destination directory for the generated Dependency-Check report. This generally maps to
     * "target/site".
     */
    @Parameter(property = "reportOutputDirectory", defaultValue = "${project.reporting.outputDirectory}", required = true)
    private File reportOutputDirectory;
    // </editor-fold>
    //<editor-fold defaultstate="collapsed" desc="Base Maven implementation">

    /**
     * Executes dependency-check.
     *
     * @throws MojoExecutionException thrown if there is an exception executing the mojo
     * @throws MojoFailureException thrown if dependency-check failed the build
     */
    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        validateAggregate();
        project.setContextValue(getOutputDirectoryContextKey(), this.outputDirectory);
        runCheck();
    }

    private void validateAggregate() throws MojoExecutionException {
        if (aggregate == true) {
            String msg = "Aggregate configuration detected - as of dependency-check 1.2.8 this no longer supported. "
                    + "Please use the aggregate goal instead.";
            throw new MojoExecutionException(msg);
        }
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     * @deprecated use {@link #generate(org.apache.maven.doxia.sink.Sink, java.util.Locale) instead.
     */
    @Deprecated
    public final void generate(@SuppressWarnings("deprecation") org.codehaus.doxia.sink.Sink sink, Locale locale) throws MavenReportException {
        generate((Sink) sink, locale);
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    public void generate(Sink sink, Locale locale) throws MavenReportException {
        try {
            validateAggregate();
        } catch (MojoExecutionException ex) {
            throw new MavenReportException(ex.getMessage());
        }
        project.setContextValue(getOutputDirectoryContextKey(), getReportOutputDirectory());
        try {
            runCheck();
        } catch (MojoExecutionException ex) {
            throw new MavenReportException(ex.getMessage(), ex);
        }
    }

    /**
     * Returns the correct output directory depending on if a site is being executed or not.
     *
     * @return the directory to write the report(s)
     * @throws MojoExecutionException thrown if there is an error loading the file path
     */
    protected File getCorrectOutputDirectory() throws MojoExecutionException {
        return getCorrectOutputDirectory(this.project);
    }

    /**
     * Returns the correct output directory depending on if a site is being executed or not.
     *
     * @param current the Maven project to get the output directory from
     * @return the directory to write the report(s)
     * @throws MojoExecutionException thrown if there is an error loading the file path
     */
    protected File getCorrectOutputDirectory(MavenProject current) throws MojoExecutionException {
        Object obj = current.getContextValue(getOutputDirectoryContextKey());
        if (obj != null && obj instanceof File) {
            return (File) obj;
        } else {
            throw new MojoExecutionException(String.format("Unable to determine output directory for '%s'", current.getName()));
        }
    }

    /**
     * Executes the dependency-check scan and generates the necassary report.
     *
     * @throws MojoExecutionException thrown if there is an exception running the scan
     */
    public abstract void runCheck() throws MojoExecutionException;

    /**
     * Sets the Reporting output directory.
     *
     * @param directory the output directory
     */
    @Override
    public void setReportOutputDirectory(File directory) {
        reportOutputDirectory = directory;
    }

    /**
     * Returns the report output directory.
     *
     * @return the report output directory
     */
    @Override
    public File getReportOutputDirectory() {
        return reportOutputDirectory;
    }

    /**
     * Returns the output directory.
     *
     * @return the output directory
     */
    public File getOutputDirectory() {
        return outputDirectory;
    }

    /**
     * Returns whether this is an external report. This method always returns true.
     *
     * @return <code>true</code>
     */
    @Override
    public final boolean isExternalReport() {
        return true;
    }

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
    //</editor-fold>

    /**
     * Initializes a new <code>Engine</code> that can be used for scanning.
     *
     * @return a newly instantiated <code>Engine</code>
     * @throws DatabaseException thrown if there is a database exception
     */
    protected Engine initializeEngine() throws DatabaseException {
        final InputStream in = BaseDependencyCheckMojo.class.getClassLoader().getResourceAsStream(LOG_PROPERTIES_FILE);
        LogUtils.prepareLogger(in, logFile);
        populateSettings();
        return new Engine(this.project, this.reactorProjects);
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

    /**
     * Tests is the artifact should be included in the scan (i.e. is the dependency in a scope that is being scanned).
     *
     * @param a the Artifact to test
     * @return <code>true</code> if the artifact is in an excluded scope; otherwise <code>false</code>
     */
    protected boolean excludeFromScan(Artifact a) {
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

    /**
     * Returns a reference to the current project. This method is used instead of auto-binding the project via component
     * annotation in concrete implementations of this. If the child has a <code>@Component MavenProject project;</code>
     * defined then the abstract class (i.e. this class) will not have access to the current project (just the way Maven
     * works with the binding).
     *
     * @return returns a reference to the current project
     */
    protected MavenProject getProject() {
        return project;
    }

    /**
     * Returns the list of Maven Projects in this build.
     *
     * @return the list of Maven Projects in this build
     */
    protected List<MavenProject> getReactorProjects() {
        return reactorProjects;
    }

    /**
     * Returns the report format.
     *
     * @return the report format
     */
    protected String getFormat() {
        return format;
    }

    /**
     * Generates the reports for a given dependency-check engine.
     *
     * @param engine a dependency-check engine
     * @param p the maven project
     * @param outputDir the directory path to write the report(s).
     */
    protected void writeReports(Engine engine, MavenProject p, File outputDir) {
        DatabaseProperties prop = null;
        CveDB cve = null;
        try {
            cve = new CveDB();
            cve.open();
            prop = cve.getDatabaseProperties();
        } catch (DatabaseException ex) {
            LOGGER.log(Level.FINE, "Unable to retrieve DB Properties", ex);
        } finally {
            if (cve != null) {
                cve.close();
            }
        }
        final ReportGenerator r = new ReportGenerator(p.getName(), engine.getDependencies(), engine.getAnalyzers(), prop);
        try {
            r.generateReports(outputDir.getAbsolutePath(), format);
        } catch (IOException ex) {
            LOGGER.log(Level.SEVERE,
                    "Unexpected exception occurred during analysis; please see the verbose error log for more details.");
            LOGGER.log(Level.FINE, null, ex);
        } catch (Throwable ex) {
            LOGGER.log(Level.SEVERE,
                    "Unexpected exception occurred during analysis; please see the verbose error log for more details.");
            LOGGER.log(Level.FINE, null, ex);
        }
    }

    //<editor-fold defaultstate="collapsed" desc="Methods to fail build or show summary">
    /**
     * Checks to see if a vulnerability has been identified with a CVSS score that is above the threshold set in the
     * configuration.
     *
     * @param dependencies the list of dependency objects
     * @throws MojoFailureException thrown if a CVSS score is found that is higher then the threshold set
     */
    protected void checkForFailure(List<Dependency> dependencies) throws MojoFailureException {
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
    protected void showSummary(List<Dependency> dependencies) {
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
     * Returns the key used to store the path to the data file that is saved by <code>writeDataFile()</code>. This key
     * is used in the <code>MavenProject.(set|get)ContextValue</code>.
     *
     * @return the key used to store the path to the data file
     */
    protected String getDataFileContextKey() {
        return "dependency-check-path-" + dataFileName;
    }

    /**
     * Returns the key used to store the path to the output directory. When generating the report in the
     * <code>executeAggregateReport()</code> the output directory should be obtained by using this key.
     *
     * @return the key used to store the path to the output directory
     */
    protected String getOutputDirectoryContextKey() {
        return "dependency-output-dir-" + dataFileName;
    }

    /**
     * Writes the scan data to disk. This is used to serialize the scan data between the "check" and "aggregate" phase.
     *
     * @param dependencies the list of dependencies to serialize
     */
    protected void writeDataFile(List<Dependency> dependencies) {
        File file = null;
        if (dependencies != null && project.getContextValue(this.getDataFileContextKey()) == null) {
            file = new File(project.getBuild().getDirectory(), dataFileName);
            OutputStream os = null;
            OutputStream bos = null;
            ObjectOutputStream out = null;
            try {
                os = new FileOutputStream(file);
                bos = new BufferedOutputStream(os);
                out = new ObjectOutputStream(bos);
                out.writeObject(dependencies);
                out.flush();

                //call reset to prevent resource leaks per
                //https://www.securecoding.cert.org/confluence/display/java/SER10-J.+Avoid+memory+and+resource+leaks+during+serialization
                out.reset();
                project.setContextValue(this.getDataFileContextKey(), file.getAbsolutePath());
                LOGGER.fine(String.format("Serialized data file written to '%s'", file.getAbsolutePath()));
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
