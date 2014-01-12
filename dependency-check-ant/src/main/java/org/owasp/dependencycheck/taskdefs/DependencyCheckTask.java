/*
 * This file is part of dependency-check-ant.
 *
 * Dependency-check-ant is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-ant is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-ant. If not, see http://www.gnu.org/licenses/.
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
     * Returns the path. If the path has not been initialized yet, this class is
     * synchronized, and will instantiate the path object.
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
     * Add a reference to a Path, FileSet, DirSet, or FileList defined
     * elsewhere.
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
     * If this is a reference, this method will add the referenced resource
     * collection to the collection of paths.
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
     * Specifies the destination directory for the generated Dependency-Check
     * report.
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
     * Specifies if the build should be failed if a CVSS score above a specified
     * level is identified. The default is 11 which means since the CVSS scores
     * are 0-10, by default the build will never fail and the CVSS score is set
     * to 11. The valid range for the fail build on CVSS is 0 to 11, where
     * anything above 10 will not cause the build to fail.
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
     * Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not
     * recommended that this be turned to false. Default is true.
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
     * The report format to be generated (HTML, XML, VULN, ALL). This
     * configuration option has no affect if using this within the Site plugin
     * unless the externalReport is set to true. Default is HTML.
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

    @Override
    public void execute() throws BuildException {
        final InputStream in = DependencyCheckTask.class.getClassLoader().getResourceAsStream(LOG_PROPERTIES_FILE);
        LogUtils.prepareLogger(in, logFile);

        dealWithReferences();
        validateConfiguration();
        populateSettings();

        final Engine engine = new Engine();
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
            final ReportGenerator reporter = new ReportGenerator(applicationName, engine.getDependencies(), engine.getAnalyzers());
            reporter.generateReports(reportOutputDirectory, reportFormat);

            if (this.failBuildOnCVSS <= 10) {
                checkForFailure(engine.getDependencies());
            }
            if (this.showSummary) {
                showSummary(engine.getDependencies());
            }
        } catch (IOException ex) {
            Logger.getLogger(DependencyCheckTask.class.getName()).log(Level.FINE, "Unable to generate dependency-check report", ex);
            throw new BuildException("Unable to generate dependency-check report", ex);
        } catch (Exception ex) {
            Logger.getLogger(DependencyCheckTask.class.getName()).log(Level.FINE, "An exception occurred; unable to continue task", ex);
            throw new BuildException("An exception occurred; unable to continue task", ex);
        }
    }

    /**
     * Validate the configuration to ensure the parameters have been properly
     * configured/initialized.
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
     * Takes the properties supplied and updates the dependency-check settings.
     * Additionally, this sets the system properties required to change the
     * proxy url, port, and connection timeout.
     */
    private void populateSettings() {
        InputStream taskProperties = null;
        try {
            taskProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
            Settings.mergeProperties(taskProperties);
        } catch (IOException ex) {
            Logger.getLogger(DependencyCheckTask.class.getName()).log(Level.WARNING, "Unable to load the dependency-check ant task.properties file.");
            Logger.getLogger(DependencyCheckTask.class.getName()).log(Level.FINE, null, ex);
        } finally {
            if (taskProperties != null) {
                try {
                    taskProperties.close();
                } catch (IOException ex) {
                    Logger.getLogger(DependencyCheckTask.class.getName()).log(Level.FINEST, null, ex);
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
    }

    /**
     * Checks to see if a vulnerability has been identified with a CVSS score
     * that is above the threshold set in the configuration.
     *
     * @param dependencies the list of dependency objects
     * @throws BuildException thrown if a CVSS score is found that is higher
     * then the threshold set
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
     * Generates a warning message listing a summary of dependencies and their
     * associated CPE and CVE entries.
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
            Logger.getLogger(DependencyCheckTask.class.getName()).log(Level.WARNING, msg);
        }
    }

    /**
     * An enumeration of supported report formats: "ALL", "HTML", "XML", "VULN",
     * etc..
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
}
