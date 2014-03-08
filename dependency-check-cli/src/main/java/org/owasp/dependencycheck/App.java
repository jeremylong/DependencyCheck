/*
 * This file is part of dependency-check-cli.
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
package org.owasp.dependencycheck;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.cli.ParseException;
import org.owasp.dependencycheck.cli.CliParser;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.LogUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * The command line interface for the DependencyCheck application.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class App {

    /**
     * The location of the log properties configuration file.
     */
    private static final String LOG_PROPERTIES_FILE = "log.properties";

    /**
     * The main method for the application.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        final App app = new App();
        app.run(args);
    }

    /**
     * Main CLI entry-point into the application.
     *
     * @param args the command line arguments
     */
    public void run(String[] args) {

        final CliParser cli = new CliParser();
        try {
            cli.parse(args);
        } catch (FileNotFoundException ex) {
            System.err.println(ex.getMessage());
            cli.printHelp();
            return;
        } catch (ParseException ex) {
            System.err.println(ex.getMessage());
            cli.printHelp();
            return;
        }

        final InputStream in = App.class.getClassLoader().getResourceAsStream(LOG_PROPERTIES_FILE);
        LogUtils.prepareLogger(in, cli.getVerboseLog());

        if (cli.isGetVersion()) {
            cli.printVersionInfo();
        } else if (cli.isRunScan()) {
            updateSettings(cli);
            runScan(cli.getReportDirectory(), cli.getReportFormat(), cli.getApplicationName(), cli.getScanFiles());
        } else {
            cli.printHelp();
        }
    }

    /**
     * Scans the specified directories and writes the dependency reports to the reportDirectory.
     *
     * @param reportDirectory the path to the directory where the reports will be written
     * @param outputFormat the output format of the report
     * @param applicationName the application name for the report
     * @param files the files/directories to scan
     */
    private void runScan(String reportDirectory, String outputFormat, String applicationName, String[] files) {
        Engine scanner = null;
        try {
            scanner = new Engine();

            for (String file : files) {
                scanner.scan(file);
            }

            scanner.analyzeDependencies();
            final List<Dependency> dependencies = scanner.getDependencies();
            DatabaseProperties prop = null;
            CveDB cve = null;
            try {
                cve = new CveDB();
                cve.open();
                prop = cve.getDatabaseProperties();
            } catch (DatabaseException ex) {
                Logger.getLogger(App.class.getName()).log(Level.FINE, "Unable to retrieve DB Properties", ex);
            } finally {
                if (cve != null) {
                    cve.close();
                }
            }
            final ReportGenerator report = new ReportGenerator(applicationName, dependencies, scanner.getAnalyzers(), prop);
            try {
                report.generateReports(reportDirectory, outputFormat);
            } catch (IOException ex) {
                Logger.getLogger(App.class.getName()).log(Level.SEVERE, "There was an IO error while attempting to generate the report.");
                Logger.getLogger(App.class.getName()).log(Level.FINE, null, ex);
            } catch (Throwable ex) {
                Logger.getLogger(App.class.getName()).log(Level.SEVERE, "There was an error while attempting to generate the report.");
                Logger.getLogger(App.class.getName()).log(Level.FINE, null, ex);
            }
        } catch (DatabaseException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, "Unable to connect to the dependency-check database; analysis has stopped");
            Logger.getLogger(App.class.getName()).log(Level.FINE, "", ex);
        } finally {
            if (scanner != null) {
                scanner.cleanup();
            }
        }
    }

    /**
     * Updates the global Settings.
     *
     * @param cli a reference to the CLI Parser that contains the command line arguments used to set the corresponding
     * settings in the core engine.
     */
    private void updateSettings(CliParser cli) {

        final boolean autoUpdate = cli.isAutoUpdate();
        final String connectionTimeout = cli.getConnectionTimeout();
        final String proxyUrl = cli.getProxyUrl();
        final String proxyPort = cli.getProxyPort();
        final String proxyUser = cli.getProxyUsername();
        final String proxyPass = cli.getProxyPassword();
        final String dataDirectory = cli.getDataDirectory();
        final File propertiesFile = cli.getPropertiesFile();
        final String suppressionFile = cli.getSuppressionFile();
        final boolean nexusDisabled = cli.isNexusDisabled();
        final String nexusUrl = cli.getNexusUrl();
        final String databaseDriverName = cli.getDatabaseDriverName();
        final String databaseDriverPath = cli.getDatabaseDriverPath();
        final String connectionString = cli.getConnectionString();
        final String databaseUser = cli.getDatabaseUser();
        final String databasePassword = cli.getDatabasePassword();
        final String additionalZipExtensions = cli.getAdditionalZipExtensions();
        final String pathToMono = cli.getPathToMono();

        if (propertiesFile != null) {
            try {
                Settings.mergeProperties(propertiesFile);
            } catch (FileNotFoundException ex) {
                final String msg = String.format("Unable to load properties file '%s'", propertiesFile.getPath());
                Logger.getLogger(App.class.getName()).log(Level.SEVERE, msg);
                Logger.getLogger(App.class.getName()).log(Level.FINE, null, ex);
            } catch (IOException ex) {
                final String msg = String.format("Unable to find properties file '%s'", propertiesFile.getPath());
                Logger.getLogger(App.class.getName()).log(Level.SEVERE, msg);
                Logger.getLogger(App.class.getName()).log(Level.FINE, null, ex);
            }
        }
        // We have to wait until we've merged the properties before attempting to set whether we use
        // the proxy for Nexus since it could be disabled in the properties, but not explicitly stated
        // on the command line
        final boolean nexusUsesProxy = cli.isNexusUsesProxy();
        if (dataDirectory != null) {
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        } else if (System.getProperty("basedir") != null) {
            final File dataDir = new File(System.getProperty("basedir"), "data");
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDir.getAbsolutePath());
        } else {
            final File jarPath = new File(App.class.getProtectionDomain().getCodeSource().getLocation().getPath());
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
        if (proxyUser != null && !proxyUser.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_USERNAME, proxyUser);
        }
        if (proxyPass != null && !proxyPass.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_PASSWORD, proxyPass);
        }
        if (connectionTimeout != null && !connectionTimeout.isEmpty()) {
            Settings.setString(Settings.KEYS.CONNECTION_TIMEOUT, connectionTimeout);
        }
        if (suppressionFile != null && !suppressionFile.isEmpty()) {
            Settings.setString(Settings.KEYS.SUPPRESSION_FILE, suppressionFile);
        }
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, !nexusDisabled);
        if (nexusUrl != null && !nexusUrl.isEmpty()) {
            Settings.setString(Settings.KEYS.ANALYZER_NEXUS_URL, nexusUrl);
        }
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_PROXY, nexusUsesProxy);
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
        if (additionalZipExtensions != null && !additionalZipExtensions.isEmpty()) {
            Settings.setString(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS, additionalZipExtensions);
        }
        if (pathToMono != null && !pathToMono.isEmpty()) {
            Settings.setString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, pathToMono);
        }
    }
}
