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

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.cli.ParseException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.org.apache.tools.ant.DirectoryScanner;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ch.qos.logback.core.FileAppender;
import org.slf4j.impl.StaticLoggerBinder;

/**
 * The command line interface for the DependencyCheck application.
 *
 * @author Jeremy Long
 */
public class App {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(App.class);

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

        if (cli.getVerboseLog() != null) {
            prepareLogger(cli.getVerboseLog());
        }

        if (cli.isGetVersion()) {
            cli.printVersionInfo();
        } else if (cli.isUpdateOnly()) {
            populateSettings(cli);
            runUpdateOnly();
        } else if (cli.isRunScan()) {
            populateSettings(cli);
            try {
                runScan(cli.getReportDirectory(), cli.getReportFormat(), cli.getApplicationName(), cli.getScanFiles(),
                        cli.getExcludeList(), cli.getSymLinkDepth());
            } catch (InvalidScanPathException ex) {
                LOGGER.error("An invalid scan path was detected; unable to scan '//*' paths");
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
     * @param symLinkDepth the depth that symbolic links will be followed
     *
     * @throws InvalidScanPathException thrown if the path to scan starts with "//"
     */
    private void runScan(String reportDirectory, String outputFormat, String applicationName, String[] files,
            String[] excludes, int symLinkDepth) throws InvalidScanPathException {
        Engine engine = null;
        try {
            engine = new Engine();
            final List<String> antStylePaths = new ArrayList<String>();
            for (String file : files) {
                final String antPath = ensureCanonicalPath(file);
                antStylePaths.add(antPath);
            }

            final Set<File> paths = new HashSet<File>();
            for (String file : antStylePaths) {
                LOGGER.debug("Scanning {}", file);
                final DirectoryScanner scanner = new DirectoryScanner();
                String include = file.replace('\\', '/');
                File baseDir;

                if (include.startsWith("//")) {
                    throw new InvalidScanPathException("Unable to scan paths specified by //");
                } else {
                    final int pos = getLastFileSeparator(include);
                    final String tmpBase = include.substring(0, pos);
                    final String tmpInclude = include.substring(pos + 1);
                    if (tmpInclude.indexOf('*') >= 0 || tmpInclude.indexOf('?') >= 0
                            || (new File(include)).isFile()) {
                        baseDir = new File(tmpBase);
                        include = tmpInclude;
                    } else {
                        baseDir = new File(tmpBase, tmpInclude);
                        include = "**/*";
                    }
                }
                //LOGGER.debug("baseDir: {}", baseDir);
                //LOGGER.debug("include: {}", include);
                scanner.setBasedir(baseDir);
                scanner.setIncludes(include);
                scanner.setMaxLevelsOfSymlinks(symLinkDepth);
                if (symLinkDepth <= 0) {
                    scanner.setFollowSymlinks(false);
                }
                if (excludes != null && excludes.length > 0) {
                    scanner.addExcludes(excludes);
                }
                scanner.scan();
                if (scanner.getIncludedFilesCount() > 0) {
                    for (String s : scanner.getIncludedFiles()) {
                        final File f = new File(baseDir, s);
                        LOGGER.debug("Found file {}", f.toString());
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
                LOGGER.debug("Unable to retrieve DB Properties", ex);
            } finally {
                if (cve != null) {
                    cve.close();
                }
            }
            final ReportGenerator report = new ReportGenerator(applicationName, dependencies, engine.getAnalyzers(), prop);
            try {
                report.generateReports(reportDirectory, outputFormat);
            } catch (IOException ex) {
                LOGGER.error("There was an IO error while attempting to generate the report.");
                LOGGER.debug("", ex);
            } catch (Throwable ex) {
                LOGGER.error("There was an error while attempting to generate the report.");
                LOGGER.debug("", ex);
            }
        } catch (DatabaseException ex) {
            LOGGER.error("Unable to connect to the dependency-check database; analysis has stopped");
            LOGGER.debug("", ex);
        } finally {
            if (engine != null) {
                engine.cleanup();
            }
        }
    }

    /**
     * Only executes the update phase of dependency-check.
     */
    private void runUpdateOnly() {
        Engine engine = null;
        try {
            engine = new Engine();
            engine.doUpdates();
        } catch (DatabaseException ex) {
            LOGGER.error("Unable to connect to the dependency-check database; analysis has stopped");
            LOGGER.debug("", ex);
        } finally {
            if (engine != null) {
                engine.cleanup();
            }
        }
    }

    /**
     * Updates the global Settings.
     *
     * @param cli a reference to the CLI Parser that contains the command line arguments used to set the corresponding settings in
     * the core engine.
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
        final boolean pyDistDisabled = cli.isPythonDistributionDisabled();
        final boolean cMakeDisabled = cli.isCmakeDisabled();
        final boolean pyPkgDisabled = cli.isPythonPackageDisabled();
        final boolean autoconfDisabled = cli.isAutoconfDisabled();
        final boolean assemblyDisabled = cli.isAssemblyDisabled();
        final boolean nuspecDisabled = cli.isNuspecDisabled();
        final boolean centralDisabled = cli.isCentralDisabled();
        final boolean nexusDisabled = cli.isNexusDisabled();
        final String nexusUrl = cli.getNexusUrl();
        final String databaseDriverName = cli.getDatabaseDriverName();
        final String databaseDriverPath = cli.getDatabaseDriverPath();
        final String connectionString = cli.getConnectionString();
        final String databaseUser = cli.getDatabaseUser();
        final String databasePassword = cli.getDatabasePassword();
        final String additionalZipExtensions = cli.getAdditionalZipExtensions();
        final String pathToMono = cli.getPathToMono();
        final String cveMod12 = cli.getModifiedCve12Url();
        final String cveMod20 = cli.getModifiedCve20Url();
        final String cveBase12 = cli.getBaseCve12Url();
        final String cveBase20 = cli.getBaseCve20Url();

        if (propertiesFile != null) {
            try {
                Settings.mergeProperties(propertiesFile);
            } catch (FileNotFoundException ex) {
                LOGGER.error("Unable to load properties file '{}'", propertiesFile.getPath());
                LOGGER.debug("", ex);
            } catch (IOException ex) {
                LOGGER.error("Unable to find properties file '{}'", propertiesFile.getPath());
                LOGGER.debug("", ex);
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
        Settings.setBoolean(Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED, !pyDistDisabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED, !pyPkgDisabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_AUTOCONF_ENABLED, !autoconfDisabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_CMAKE_ENABLED, !cMakeDisabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_NUSPEC_ENABLED, !nuspecDisabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, !assemblyDisabled);
        Settings.setBoolean(Settings.KEYS.ANALYZER_OPENSSL_ENABLED, !cli.isOpenSSLDisabled());

        Settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, !centralDisabled);
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
        if (cveBase12 != null && !cveBase12.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_SCHEMA_1_2, cveBase12);
            Settings.setString(Settings.KEYS.CVE_SCHEMA_2_0, cveBase20);
            Settings.setString(Settings.KEYS.CVE_MODIFIED_12_URL, cveMod12);
            Settings.setString(Settings.KEYS.CVE_MODIFIED_20_URL, cveMod20);
        }
    }

    /**
     * Creates a file appender and adds it to logback.
     *
     * @param verboseLog the path to the verbose log file
     */
    private void prepareLogger(String verboseLog) {
        final StaticLoggerBinder loggerBinder = StaticLoggerBinder.getSingleton();
        final LoggerContext context = (LoggerContext) loggerBinder.getLoggerFactory();

        final PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setPattern("%d %C:%L%n%-5level - %msg%n");
        encoder.setContext(context);
        encoder.start();
        final FileAppender fa = new FileAppender();
        fa.setAppend(true);
        fa.setEncoder(encoder);
        fa.setContext(context);
        fa.setFile(verboseLog);
        final File f = new File(verboseLog);
        String name = f.getName();
        final int i = name.lastIndexOf('.');
        if (i > 1) {
            name = name.substring(0, i);
        }
        fa.setName(name);
        fa.start();
        final ch.qos.logback.classic.Logger rootLogger = context.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
        rootLogger.addAppender(fa);
    }

    /**
     * Takes a path and resolves it to be a canonical & absolute path. The caveats are that this method will take an Ant style
     * file selector path (../someDir/**\/*.jar) and convert it to an absolute/canonical path (at least to the left of the first *
     * or ?).
     *
     * @param path the path to canonicalize
     * @return the canonical path
     */
    protected String ensureCanonicalPath(String path) {
        String basePath = null;
        String wildCards = null;
        final String file = path.replace('\\', '/');
        if (file.contains("*") || file.contains("?")) {

            int pos = getLastFileSeparator(file);
            if (pos < 0) {
                return file;
            }
            pos += 1;
            basePath = file.substring(0, pos);
            wildCards = file.substring(pos);
        } else {
            basePath = file;
        }

        File f = new File(basePath);
        try {
            f = f.getCanonicalFile();
            if (wildCards != null) {
                f = new File(f, wildCards);
            }
        } catch (IOException ex) {
            LOGGER.warn("Invalid path '{}' was provided.", path);
            LOGGER.debug("Invalid path provided", ex);
        }
        return f.getAbsolutePath().replace('\\', '/');
    }

    /**
     * Returns the position of the last file separator.
     *
     * @param file a file path
     * @return the position of the last file separator
     */
    private int getLastFileSeparator(String file) {
        if (file.contains("*") || file.contains("?")) {
            int p1 = file.indexOf('*');
            int p2 = file.indexOf('?');
            p1 = p1 > 0 ? p1 : file.length();
            p2 = p2 > 0 ? p2 : file.length();
            int pos = p1 < p2 ? p1 : p2;
            pos = file.lastIndexOf('/', pos);
            return pos;
        } else {
            return file.lastIndexOf('/');
        }
    }
}
