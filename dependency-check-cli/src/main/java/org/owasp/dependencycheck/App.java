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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.cli.ParseException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.org.apache.tools.ant.DirectoryScanner;
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
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(App.class.getName());

    /**
     * The main method for the application.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            Settings.initialize();
            final App app = new App();
            app.run(args);
        } finally {
            Settings.cleanup(true);
        }
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
            populateSettings(cli);
            try {
                runScan(cli.getReportDirectory(), cli.getReportFormat(), cli.getApplicationName(), cli.getScanFiles(), cli.getExcludeList());
            } catch (InvalidScanPathException ex) {
                Logger.getLogger(App.class.getName()).log(Level.SEVERE, "An invalid scan path was detected; unable to scan '//*' paths");
            }
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
     * @param excludes the patterns for files/directories to exclude
     *
     * @throws InvalidScanPathException thrown if the path to scan starts with "//"
     */
    private void runScan(String reportDirectory, String outputFormat, String applicationName, String[] files,
            String[] excludes) throws InvalidScanPathException {
        Engine engine = null;
        try {
            engine = new Engine();
            List<String> antStylePaths = new ArrayList<String>();
            if (excludes == null || excludes.length == 0) {
                for (String file : files) {
                    if (file.contains("*") || file.contains("?")) {
                        antStylePaths.add(file);
                    } else {
                        engine.scan(file);
                    }
                }
            } else {
                antStylePaths = Arrays.asList(files);
            }

            final Set<File> paths = new HashSet<File>();
            for (String file : antStylePaths) {
                final DirectoryScanner scanner = new DirectoryScanner();
                String include = file.replace('\\', '/');
                File baseDir;

                if (include.startsWith("//")) {
                    throw new InvalidScanPathException("Unable to scan paths specified by //");
                } else if (include.startsWith("./")) {
                    baseDir = new File(".");
                    include = include.substring(2);
                } else if (include.startsWith("/")) {
                    baseDir = new File("/");
                    include = include.substring(1);
                } else if (include.contains("/")) {
                    final int pos = include.indexOf('/');
                    final String tmp = include.substring(0, pos);
                    if (tmp.contains("*") || tmp.contains("?")) {
                        baseDir = new File(".");
                    } else {
                        baseDir = new File(tmp);
                        include = include.substring(pos + 1);
                    }
                } else { //no path info - must just be a file in the working directory
                    baseDir = new File(".");
                }
                scanner.setBasedir(baseDir);
                scanner.setIncludes(include);
                if (excludes != null && excludes.length > 0) {
                    scanner.addExcludes(excludes);
                }
                scanner.scan();
                if (scanner.getIncludedFilesCount() > 0) {
                    for (String s : scanner.getIncludedFiles()) {
                        final File f = new File(baseDir, s);
                        paths.add(f);
                    }
                }
            }
            engine.scan(paths);

            engine.analyzeDependencies();
            final List<Dependency> dependencies = engine.getDependencies();
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
            final ReportGenerator report = new ReportGenerator(applicationName, dependencies, engine.getAnalyzers(), prop);
            try {
                report.generateReports(reportDirectory, outputFormat);
            } catch (IOException ex) {
                LOGGER.log(Level.SEVERE, "There was an IO error while attempting to generate the report.");
                LOGGER.log(Level.FINE, null, ex);
            } catch (Throwable ex) {
                LOGGER.log(Level.SEVERE, "There was an error while attempting to generate the report.");
                LOGGER.log(Level.FINE, null, ex);
            }
        } catch (DatabaseException ex) {
            LOGGER.log(Level.SEVERE, "Unable to connect to the dependency-check database; analysis has stopped");
            LOGGER.log(Level.FINE, "", ex);
        } finally {
            if (engine != null) {
                engine.cleanup();
            }
        }
    }

    /**
     * Updates the global Settings.
     *
     * @param cli a reference to the CLI Parser that contains the command line arguments used to set the corresponding
     * settings in the core engine.
     */
    private void populateSettings(CliParser cli) {

        final boolean autoUpdate = cli.isAutoUpdate();
        final String connectionTimeout = cli.getConnectionTimeout();
        final String proxyServer = cli.getProxyServer();
        final String proxyPort = cli.getProxyPort();
        final String proxyUser = cli.getProxyUsername();
        final String proxyPass = cli.getProxyPassword();
        final String dataDirectory = cli.getDataDirectory();
        final File propertiesFile = cli.getPropertiesFile();
        final String suppressionFile = cli.getSuppressionFile();
        final boolean jarDisabled = cli.isJarDisabled();
        final boolean archiveDisabled = cli.isArchiveDisabled();
        final boolean assemblyDisabled = cli.isAssemblyDisabled();
        final boolean nuspecDisabled = cli.isNuspecDisabled();
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
                LOGGER.log(Level.SEVERE, msg);
                LOGGER.log(Level.FINE, null, ex);
            } catch (IOException ex) {
                final String msg = String.format("Unable to find properties file '%s'", propertiesFile.getPath());
                LOGGER.log(Level.SEVERE, msg);
                LOGGER.log(Level.FINE, null, ex);
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
        if (proxyServer != null && !proxyServer.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_SERVER, proxyServer);
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

        //File Type Analyzer Settings
        Settings.setBoolean(Settings.KEYS.ANALYZER_JAR_ENABLED, !jarDisabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, !archiveDisabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_NUSPEC_ENABLED, !nuspecDisabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, !assemblyDisabled);

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
