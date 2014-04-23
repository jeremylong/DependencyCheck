/*
 * This file is part of dependency-check-ant.
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
package org.owasp.dependencycheck.taskdefs;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.types.EnumeratedAttribute;
import org.apache.tools.ant.types.Reference;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.ResourceCollection;
import org.apache.tools.ant.types.resources.FileProvider;
import org.apache.tools.ant.types.resources.Resources;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.reporting.ReportGenerator.Format;
import org.owasp.dependencycheck.utils.LogUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * An Ant task definition to execute dependency-check during an Ant build.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DependencyCheckTask extends Task {

    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "task.properties";
    /**
     * Name of the logging properties file.
     */
    private static final String LOG_PROPERTIES_FILE = "log.properties";
    /**
     * System specific new line character.
     */
    private static final String NEW_LINE = System.getProperty("line.separator", "\n").intern();
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(DependencyCheckTask.class.getName());

    /**
     * Construct a new DependencyCheckTask.
     */
    public DependencyCheckTask() {
        super();
    }
    //The following code was copied Apache Ant PathConvert
    //BEGIN COPY from org.apache.tools.ant.taskdefs.PathConvert
    /**
     * Path to be converted
     */
    private Resources path = null;
    /**
     * Reference to path/fileset to convert
     */
    private Reference refid = null;

    /**
     * Add an arbitrary ResourceCollection.
     *
     * @param rc the ResourceCollection to add.
     * @since Ant 1.7
     */
    public void add(ResourceCollection rc) {
        if (isReference()) {
            throw new BuildException("Nested elements are not allowed when using the refid attribute.");
        }
        getPath().add(rc);
    }

    /**
     * Returns the path. If the path has not been initialized yet, this class is synchronized, and will instantiate the
     * path object.
     *
     * @return the path
     */
    private synchronized Resources getPath() {
        if (path == null) {
            path = new Resources(getProject());
            path.setCache(true);
        }
        return path;
    }

    /**
     * Learn whether the refid attribute of this element been set.
     *
     * @return true if refid is valid.
     */
    public boolean isReference() {
        return refid != null;
    }

    /**
     * Add a reference to a Path, FileSet, DirSet, or FileList defined elsewhere.
     *
     * @param r the reference to a path, fileset, dirset or filelist.
     */
    public void setRefid(Reference r) {
        if (path != null) {
            throw new BuildException("Nested elements are not allowed when using the refid attribute.");
        }
        refid = r;
    }

    /**
     * If this is a reference, this method will add the referenced resource collection to the collection of paths.
     *
     * @throws BuildException if the reference is not to a resource collection
     */
    private void dealWithReferences() throws BuildException {
        if (isReference()) {
            final Object o = refid.getReferencedObject(getProject());
            if (!(o instanceof ResourceCollection)) {
                throw new BuildException("refid '" + refid.getRefId()
                        + "' does not refer to a resource collection.");
            }
            getPath().add((ResourceCollection) o);
        }
    }
    // END COPY from org.apache.tools.ant.taskdefs
    /**
     * The application name for the report.
     */
    private String applicationName = "Dependency-Check";

    /**
     * Get the value of applicationName.
     *
     * @return the value of applicationName
     */
    public String getApplicationName() {
        return applicationName;
    }

    /**
     * Set the value of applicationName.
     *
     * @param applicationName new value of applicationName
     */
    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }
    /**
     * The location of the data directory that contains
     */
    private String dataDirectory = null;

    /**
     * Get the value of dataDirectory.
     *
     * @return the value of dataDirectory
     */
    public String getDataDirectory() {
        return dataDirectory;
    }

    /**
     * Set the value of dataDirectory.
     *
     * @param dataDirectory new value of dataDirectory
     */
    public void setDataDirectory(String dataDirectory) {
        this.dataDirectory = dataDirectory;
    }
    /**
     * Specifies the destination directory for the generated Dependency-Check report.
     */
    private String reportOutputDirectory = ".";

    /**
     * Get the value of reportOutputDirectory.
     *
     * @return the value of reportOutputDirectory
     */
    public String getReportOutputDirectory() {
        return reportOutputDirectory;
    }

    /**
     * Set the value of reportOutputDirectory.
     *
     * @param reportOutputDirectory new value of reportOutputDirectory
     */
    public void setReportOutputDirectory(String reportOutputDirectory) {
        this.reportOutputDirectory = reportOutputDirectory;
    }
    /**
     * Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11
     * which means since the CVSS scores are 0-10, by default the build will never fail and the CVSS score is set to 11.
     * The valid range for the fail build on CVSS is 0 to 11, where anything above 10 will not cause the build to fail.
     */
    private float failBuildOnCVSS = 11;

    /**
     * Get the value of failBuildOnCVSS.
     *
     * @return the value of failBuildOnCVSS
     */
    public float getFailBuildOnCVSS() {
        return failBuildOnCVSS;
    }

    /**
     * Set the value of failBuildOnCVSS.
     *
     * @param failBuildOnCVSS new value of failBuildOnCVSS
     */
    public void setFailBuildOnCVSS(float failBuildOnCVSS) {
        this.failBuildOnCVSS = failBuildOnCVSS;
    }
    /**
     * Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to
     * false. Default is true.
     */
    private boolean autoUpdate = true;

    /**
     * Get the value of autoUpdate.
     *
     * @return the value of autoUpdate
     */
    public boolean isAutoUpdate() {
        return autoUpdate;
    }

    /**
     * Set the value of autoUpdate.
     *
     * @param autoUpdate new value of autoUpdate
     */
    public void setAutoUpdate(boolean autoUpdate) {
        this.autoUpdate = autoUpdate;
    }
    /**
     * The report format to be generated (HTML, XML, VULN, ALL). This configuration option has no affect if using this
     * within the Site plugin unless the externalReport is set to true. Default is HTML.
     */
    private String reportFormat = "HTML";

    /**
     * Get the value of reportFormat.
     *
     * @return the value of reportFormat
     */
    public String getReportFormat() {
        return reportFormat;
    }

    /**
     * Set the value of reportFormat.
     *
     * @param reportFormat new value of reportFormat
     */
    public void setReportFormat(ReportFormats reportFormat) {
        this.reportFormat = reportFormat.getValue();
    }
    /**
     * The Proxy URL.
     */
    private String proxyUrl;

    /**
     * Get the value of proxyUrl.
     *
     * @return the value of proxyUrl
     */
    public String getProxyUrl() {
        return proxyUrl;
    }

    /**
     * Set the value of proxyUrl.
     *
     * @param proxyUrl new value of proxyUrl
     */
    public void setProxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
    }
    /**
     * The Proxy Port.
     */
    private String proxyPort;

    /**
     * Get the value of proxyPort.
     *
     * @return the value of proxyPort
     */
    public String getProxyPort() {
        return proxyPort;
    }

    /**
     * Set the value of proxyPort.
     *
     * @param proxyPort new value of proxyPort
     */
    public void setProxyPort(String proxyPort) {
        this.proxyPort = proxyPort;
    }
    /**
     * The Proxy username.
     */
    private String proxyUsername;

    /**
     * Get the value of proxyUsername.
     *
     * @return the value of proxyUsername
     */
    public String getProxyUsername() {
        return proxyUsername;
    }

    /**
     * Set the value of proxyUsername.
     *
     * @param proxyUsername new value of proxyUsername
     */
    public void setProxyUsername(String proxyUsername) {
        this.proxyUsername = proxyUsername;
    }
    /**
     * The Proxy password.
     */
    private String proxyPassword;

    /**
     * Get the value of proxyPassword.
     *
     * @return the value of proxyPassword
     */
    public String getProxyPassword() {
        return proxyPassword;
    }

    /**
     * Set the value of proxyPassword.
     *
     * @param proxyPassword new value of proxyPassword
     */
    public void setProxyPassword(String proxyPassword) {
        this.proxyPassword = proxyPassword;
    }
    /**
     * The Connection Timeout.
     */
    private String connectionTimeout;

    /**
     * Get the value of connectionTimeout.
     *
     * @return the value of connectionTimeout
     */
    public String getConnectionTimeout() {
        return connectionTimeout;
    }

    /**
     * Set the value of connectionTimeout.
     *
     * @param connectionTimeout new value of connectionTimeout
     */
    public void setConnectionTimeout(String connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }
    /**
     * The file path used for verbose logging.
     */
    private String logFile = null;

    /**
     * Get the value of logFile.
     *
     * @return the value of logFile
     */
    public String getLogFile() {
        return logFile;
    }

    /**
     * Set the value of logFile.
     *
     * @param logFile new value of logFile
     */
    public void setLogFile(String logFile) {
        this.logFile = logFile;
    }
    /**
     * The path to the suppression file.
     */
    private String suppressionFile;

    /**
     * Get the value of suppressionFile.
     *
     * @return the value of suppressionFile
     */
    public String getSuppressionFile() {
        return suppressionFile;
    }

    /**
     * Set the value of suppressionFile.
     *
     * @param suppressionFile new value of suppressionFile
     */
    public void setSuppressionFile(String suppressionFile) {
        this.suppressionFile = suppressionFile;
    }
    /**
     * flag indicating whether or not to show a summary of findings.
     */
    private boolean showSummary = true;

    /**
     * Get the value of showSummary.
     *
     * @return the value of showSummary
     */
    public boolean isShowSummary() {
        return showSummary;
    }

    /**
     * Set the value of showSummary.
     *
     * @param showSummary new value of showSummary
     */
    public void setShowSummary(boolean showSummary) {
        this.showSummary = showSummary;
    }

    /**
     * Sets whether or not the analyzer is enabled.
     *
     * @param jarAnalyzerEnabled the value of the new setting
     */
    public void setJarAnalyzerEnabled(boolean jarAnalyzerEnabled) {
        this.jarAnalyzerEnabled = jarAnalyzerEnabled;
    }
    /**
     * Whether or not the Archive Analyzer is enabled.
     */
    private boolean archiveAnalyzerEnabled = true;

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return true if the analyzer is enabled
     */
    public boolean isArchiveAnalyzerEnabled() {
        return archiveAnalyzerEnabled;
    }
    /**
     * Whether or not the .NET Assembly Analyzer is enabled.
     */
    private boolean assemblyAnalyzerEnabled = true;

    /**
     * Sets whether or not the analyzer is enabled.
     *
     * @param archiveAnalyzerEnabled the value of the new setting
     */
    public void setArchiveAnalyzerEnabled(boolean archiveAnalyzerEnabled) {
        this.archiveAnalyzerEnabled = archiveAnalyzerEnabled;
    }

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return true if the analyzer is enabled
     */
    public boolean isAssemblyAnalyzerEnabled() {
        return assemblyAnalyzerEnabled;
    }

    /**
     * Sets whether or not the analyzer is enabled.
     *
     * @param assemblyAnalyzerEnabled the value of the new setting
     */
    public void setAssemblyAnalyzerEnabled(boolean assemblyAnalyzerEnabled) {
        this.assemblyAnalyzerEnabled = assemblyAnalyzerEnabled;
    }
    /**
     * Whether or not the .NET Nuspec Analyzer is enabled.
     */
    private boolean nuspecAnalyzerEnabled = true;

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return true if the analyzer is enabled
     */
    public boolean isNuspecAnalyzerEnabled() {
        return nuspecAnalyzerEnabled;
    }

    /**
     * Sets whether or not the analyzer is enabled.
     *
     * @param nuspecAnalyzerEnabled the value of the new setting
     */
    public void setNuspecAnalyzerEnabled(boolean nuspecAnalyzerEnabled) {
        this.nuspecAnalyzerEnabled = nuspecAnalyzerEnabled;
    }

    /**
     * Whether or not the nexus analyzer is enabled.
     */
    private boolean nexusAnalyzerEnabled = true;

    /**
     * Get the value of nexusAnalyzerEnabled.
     *
     * @return the value of nexusAnalyzerEnabled
     */
    public boolean isNexusAnalyzerEnabled() {
        return nexusAnalyzerEnabled;
    }

    /**
     * Set the value of nexusAnalyzerEnabled.
     *
     * @param nexusAnalyzerEnabled new value of nexusAnalyzerEnabled
     */
    public void setNexusAnalyzerEnabled(boolean nexusAnalyzerEnabled) {
        this.nexusAnalyzerEnabled = nexusAnalyzerEnabled;
    }

    /**
     * The URL of the Nexus server.
     */
    private String nexusUrl;

    /**
     * Get the value of nexusUrl.
     *
     * @return the value of nexusUrl
     */
    public String getNexusUrl() {
        return nexusUrl;
    }

    /**
     * Set the value of nexusUrl.
     *
     * @param nexusUrl new value of nexusUrl
     */
    public void setNexusUrl(String nexusUrl) {
        this.nexusUrl = nexusUrl;
    }
    /**
     * Whether or not the defined proxy should be used when connecting to Nexus.
     */
    private boolean nexusUsesProxy = true;

    /**
     * Get the value of nexusUsesProxy.
     *
     * @return the value of nexusUsesProxy
     */
    public boolean isNexusUsesProxy() {
        return nexusUsesProxy;
    }

    /**
     * Set the value of nexusUsesProxy.
     *
     * @param nexusUsesProxy new value of nexusUsesProxy
     */
    public void setNexusUsesProxy(boolean nexusUsesProxy) {
        this.nexusUsesProxy = nexusUsesProxy;
    }

    /**
     * The database driver name; such as org.h2.Driver.
     */
    private String databaseDriverName;

    /**
     * Get the value of databaseDriverName.
     *
     * @return the value of databaseDriverName
     */
    public String getDatabaseDriverName() {
        return databaseDriverName;
    }

    /**
     * Set the value of databaseDriverName.
     *
     * @param databaseDriverName new value of databaseDriverName
     */
    public void setDatabaseDriverName(String databaseDriverName) {
        this.databaseDriverName = databaseDriverName;
    }

    /**
     * The path to the database driver JAR file if it is not on the class path.
     */
    private String databaseDriverPath;

    /**
     * Get the value of databaseDriverPath.
     *
     * @return the value of databaseDriverPath
     */
    public String getDatabaseDriverPath() {
        return databaseDriverPath;
    }

    /**
     * Set the value of databaseDriverPath.
     *
     * @param databaseDriverPath new value of databaseDriverPath
     */
    public void setDatabaseDriverPath(String databaseDriverPath) {
        this.databaseDriverPath = databaseDriverPath;
    }
    /**
     * The database connection string.
     */
    private String connectionString;

    /**
     * Get the value of connectionString.
     *
     * @return the value of connectionString
     */
    public String getConnectionString() {
        return connectionString;
    }

    /**
     * Set the value of connectionString.
     *
     * @param connectionString new value of connectionString
     */
    public void setConnectionString(String connectionString) {
        this.connectionString = connectionString;
    }
    /**
     * The user name for connecting to the database.
     */
    private String databaseUser;

    /**
     * Get the value of databaseUser.
     *
     * @return the value of databaseUser
     */
    public String getDatabaseUser() {
        return databaseUser;
    }

    /**
     * Set the value of databaseUser.
     *
     * @param databaseUser new value of databaseUser
     */
    public void setDatabaseUser(String databaseUser) {
        this.databaseUser = databaseUser;
    }

    /**
     * The password to use when connecting to the database.
     */
    private String databasePassword;

    /**
     * Get the value of databasePassword.
     *
     * @return the value of databasePassword
     */
    public String getDatabasePassword() {
        return databasePassword;
    }

    /**
     * Set the value of databasePassword.
     *
     * @param databasePassword new value of databasePassword
     */
    public void setDatabasePassword(String databasePassword) {
        this.databasePassword = databasePassword;
    }

    /**
     * Additional ZIP File extensions to add analyze. This should be a comma-separated list of file extensions to treat
     * like ZIP files.
     */
    private String zipExtensions;

    /**
     * Get the value of zipExtensions.
     *
     * @return the value of zipExtensions
     */
    public String getZipExtensions() {
        return zipExtensions;
    }

    /**
     * Set the value of zipExtensions.
     *
     * @param zipExtensions new value of zipExtensions
     */
    public void setZipExtensions(String zipExtensions) {
        this.zipExtensions = zipExtensions;
    }

    /**
     * The url for the modified NVD CVE (1.2 schema).
     */
    private String cveUrl12Modified;

    /**
     * Get the value of cveUrl12Modified.
     *
     * @return the value of cveUrl12Modified
     */
    public String getCveUrl12Modified() {
        return cveUrl12Modified;
    }

    /**
     * Set the value of cveUrl12Modified.
     *
     * @param cveUrl12Modified new value of cveUrl12Modified
     */
    public void setCveUrl12Modified(String cveUrl12Modified) {
        this.cveUrl12Modified = cveUrl12Modified;
    }

    /**
     * The url for the modified NVD CVE (2.0 schema).
     */
    private String cveUrl20Modified;

    /**
     * Get the value of cveUrl20Modified.
     *
     * @return the value of cveUrl20Modified
     */
    public String getCveUrl20Modified() {
        return cveUrl20Modified;
    }

    /**
     * Set the value of cveUrl20Modified.
     *
     * @param cveUrl20Modified new value of cveUrl20Modified
     */
    public void setCveUrl20Modified(String cveUrl20Modified) {
        this.cveUrl20Modified = cveUrl20Modified;
    }

    /**
     * Base Data Mirror URL for CVE 1.2.
     */
    private String cveUrl12Base;

    /**
     * Get the value of cveUrl12Base.
     *
     * @return the value of cveUrl12Base
     */
    public String getCveUrl12Base() {
        return cveUrl12Base;
    }

    /**
     * Set the value of cveUrl12Base.
     *
     * @param cveUrl12Base new value of cveUrl12Base
     */
    public void setCveUrl12Base(String cveUrl12Base) {
        this.cveUrl12Base = cveUrl12Base;
    }

    /**
     * Data Mirror URL for CVE 2.0.
     */
    private String cveUrl20Base;

    /**
     * Get the value of cveUrl20Base.
     *
     * @return the value of cveUrl20Base
     */
    public String getCveUrl20Base() {
        return cveUrl20Base;
    }

    /**
     * Set the value of cveUrl20Base.
     *
     * @param cveUrl20Base new value of cveUrl20Base
     */
    public void setCveUrl20Base(String cveUrl20Base) {
        this.cveUrl20Base = cveUrl20Base;
    }
    /**
     * The path to Mono for .NET assembly analysis on non-windows systems.
     */
    private String pathToMono;

    /**
     * Get the value of pathToMono.
     *
     * @return the value of pathToMono
     */
    public String getPathToMono() {
        return pathToMono;
    }

    /**
     * Set the value of pathToMono.
     *
     * @param pathToMono new value of pathToMono
     */
    public void setPathToMono(String pathToMono) {
        this.pathToMono = pathToMono;
    }

    @Override
    public void execute() throws BuildException {
        final InputStream in = DependencyCheckTask.class.getClassLoader().getResourceAsStream(LOG_PROPERTIES_FILE);
        LogUtils.prepareLogger(in, logFile);

        dealWithReferences();
        validateConfiguration();
        populateSettings();

        Engine engine = null;
        try {
            engine = new Engine();

            for (Resource resource : path) {
                final FileProvider provider = resource.as(FileProvider.class);
                if (provider != null) {
                    final File file = provider.getFile();
                    if (file != null && file.exists()) {
                        engine.scan(file);
                    }
                }
            }
            try {
                engine.analyzeDependencies();
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
                final ReportGenerator reporter = new ReportGenerator(applicationName, engine.getDependencies(), engine.getAnalyzers(), prop);
                reporter.generateReports(reportOutputDirectory, reportFormat);

                if (this.failBuildOnCVSS <= 10) {
                    checkForFailure(engine.getDependencies());
                }
                if (this.showSummary) {
                    showSummary(engine.getDependencies());
                }
            } catch (IOException ex) {
                LOGGER.log(Level.FINE, "Unable to generate dependency-check report", ex);
                throw new BuildException("Unable to generate dependency-check report", ex);
            } catch (Exception ex) {
                LOGGER.log(Level.FINE, "An exception occurred; unable to continue task", ex);
                throw new BuildException("An exception occurred; unable to continue task", ex);
            }
        } catch (DatabaseException ex) {
            LOGGER.log(Level.SEVERE, "Unable to connect to the dependency-check database; analysis has stopped");
            LOGGER.log(Level.FINE, "", ex);
        } finally {
            Settings.cleanup();
            if (engine != null) {
                engine.cleanup();
            }
        }
    }

    /**
     * Validate the configuration to ensure the parameters have been properly configured/initialized.
     *
     * @throws BuildException if the task was not configured correctly.
     */
    private void validateConfiguration() throws BuildException {
        if (path == null) {
            throw new BuildException("No project dependencies have been defined to analyze.");
        }
        if (failBuildOnCVSS < 0 || failBuildOnCVSS > 11) {
            throw new BuildException("Invalid configuration, failBuildOnCVSS must be between 0 and 11.");
        }
    }

    /**
     * Takes the properties supplied and updates the dependency-check settings. Additionally, this sets the system
     * properties required to change the proxy url, port, and connection timeout.
     */
    private void populateSettings() {
        Settings.initialize();
        InputStream taskProperties = null;
        try {
            taskProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
            Settings.mergeProperties(taskProperties);
        } catch (IOException ex) {
            LOGGER.log(Level.WARNING, "Unable to load the dependency-check ant task.properties file.");
            LOGGER.log(Level.FINE, null, ex);
        } finally {
            if (taskProperties != null) {
                try {
                    taskProperties.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.FINEST, null, ex);
                }
            }
        }
        if (dataDirectory != null) {
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        } else {
            final File jarPath = new File(DependencyCheckTask.class.getProtectionDomain().getCodeSource().getLocation().getPath());
            final File base = jarPath.getParentFile();
            final String sub = Settings.getString(Settings.KEYS.DATA_DIRECTORY);
            final File dataDir = new File(base, sub);
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDir.getAbsolutePath());
        }

        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);

        if (proxyUrl != null && !proxyUrl.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_URL, proxyUrl);
        }
        if (proxyPort != null && !proxyPort.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_PORT, proxyPort);
        }
        if (proxyUsername != null && !proxyUsername.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_USERNAME, proxyUsername);
        }
        if (proxyPassword != null && !proxyPassword.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_PASSWORD, proxyPassword);
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
     * Checks to see if a vulnerability has been identified with a CVSS score that is above the threshold set in the
     * configuration.
     *
     * @param dependencies the list of dependency objects
     * @throws BuildException thrown if a CVSS score is found that is higher then the threshold set
     */
    private void checkForFailure(List<Dependency> dependencies) throws BuildException {
        final StringBuilder ids = new StringBuilder();
        for (Dependency d : dependencies) {
            for (Vulnerability v : d.getVulnerabilities()) {
                if (v.getCvssScore() >= failBuildOnCVSS) {
                    if (ids.length() == 0) {
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
            throw new BuildException(msg);
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
            LOGGER.log(Level.WARNING, msg);
        }
    }

    /**
     * An enumeration of supported report formats: "ALL", "HTML", "XML", "VULN", etc..
     */
    public static class ReportFormats extends EnumeratedAttribute {

        /**
         * Returns the list of values for the report format.
         *
         * @return the list of values for the report format
         */
        @Override
        public String[] getValues() {
            int i = 0;
            final Format[] formats = Format.values();
            final String[] values = new String[formats.length];
            for (Format format : formats) {
                values[i++] = format.name();
            }
            return values;
        }
    }

    /**
     * Whether or not the Jar Analyzer is enabled.
     */
    private boolean jarAnalyzerEnabled = true;

    /**
     * Returns whether or not the analyzer is enabled.
     *
     * @return true if the analyzer is enabled
     */
    public boolean isJarAnalyzerEnabled() {
        return jarAnalyzerEnabled;
    }
}
