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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.cli.ParseException;
import org.apache.tools.ant.DirectoryScanner;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.apache.tools.ant.types.LogLevel;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.CveUrlParser;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.impl.StaticLoggerBinder;

import ch.qos.logback.core.FileAppender;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.filter.ThresholdFilter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import java.util.TreeSet;
import org.owasp.dependencycheck.utils.SeverityUtil;

/**
 * The command line interface for the DependencyCheck application.
 *
 * @author Jeremy Long
 */
@SuppressWarnings("squid:S106")
public class App {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(App.class);
    /**
     * Properties file error message.
     */
    private static final String ERROR_LOADING_PROPERTIES_FILE = "Error loading properties file";
    /**
     * The configured settings.
     */
    private Settings settings;

    /**
     * The main method for the application.
     *
     * @param args the command line arguments
     */
    @SuppressWarnings("squid:S4823")
    public static void main(String[] args) {
        final int exitCode;
        final App app = new App();
        exitCode = app.run(args);
        LOGGER.debug("Exit code: {}", exitCode);
        System.exit(exitCode);
    }

    /**
     * Builds the App object.
     */
    public App() {
        settings = new Settings();
    }

    /**
     * Builds the App object; this method is used for testing.
     *
     * @param settings the configured settings
     */
    protected App(Settings settings) {
        this.settings = settings;
    }

    /**
     * Main CLI entry-point into the application.
     *
     * @param args the command line arguments
     * @return the exit code to return
     */
    public int run(String[] args) {
        int exitCode = 0;
        final CliParser cli = new CliParser(settings);

        try {
            cli.parse(args);
        } catch (FileNotFoundException ex) {
            System.err.println(ex.getMessage());
            cli.printHelp();
            return -1;
        } catch (ParseException ex) {
            System.err.println(ex.getMessage());
            cli.printHelp();
            return -2;
        }
        final String verboseLog = cli.getStringArgument(CliParser.ARGUMENT.VERBOSE_LOG);
        if (verboseLog != null) {
            prepareLogger(verboseLog);
        }

        if (cli.isPurge()) {
            final String connStr = cli.getStringArgument(CliParser.ARGUMENT.CONNECTION_STRING);
            if (connStr != null) {
                LOGGER.error("Unable to purge the database when using a non-default connection string");
                exitCode = -3;
            } else {
                try {
                    populateSettings(cli);
                } catch (InvalidSettingException ex) {
                    LOGGER.error(ex.getMessage());
                    LOGGER.debug(ERROR_LOADING_PROPERTIES_FILE, ex);
                    exitCode = -4;
                    return exitCode;
                }
                try (Engine engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING, settings)) {
                    if (!engine.purge()) {
                        exitCode = -7;
                        return exitCode;
                    }
                } finally {
                    settings.cleanup();
                }
            }
        } else if (cli.isGetVersion()) {
            cli.printVersionInfo();
        } else if (cli.isUpdateOnly()) {
            try {
                populateSettings(cli);
                settings.setBoolean(Settings.KEYS.AUTO_UPDATE, true);
            } catch (InvalidSettingException ex) {
                LOGGER.error(ex.getMessage());
                LOGGER.debug(ERROR_LOADING_PROPERTIES_FILE, ex);
                exitCode = -4;
                return exitCode;
            }
            try {
                runUpdateOnly();
            } catch (UpdateException ex) {
                LOGGER.error(ex.getMessage(), ex);
                exitCode = -8;
            } catch (DatabaseException ex) {
                LOGGER.error(ex.getMessage(), ex);
                exitCode = -9;
            } finally {
                settings.cleanup();
            }
        } else if (cli.isRunScan()) {
            try {
                populateSettings(cli);
            } catch (InvalidSettingException ex) {
                LOGGER.error(ex.getMessage(), ex);
                LOGGER.debug(ERROR_LOADING_PROPERTIES_FILE, ex);
                exitCode = -4;
                return exitCode;
            }
            try {
                final String[] scanFiles = cli.getScanFiles();
                if (scanFiles != null) {
                    exitCode = runScan(cli.getReportDirectory(), cli.getReportFormat(), cli.getProjectName(), scanFiles,
                            cli.getExcludeList(), cli.getSymLinkDepth(), cli.getFailOnCVSS());
                } else {
                    LOGGER.error("No scan files configured");
                }
            } catch (DatabaseException ex) {
                LOGGER.error(ex.getMessage());
                LOGGER.debug("database exception", ex);
                exitCode = -11;
            } catch (ReportException ex) {
                LOGGER.error(ex.getMessage());
                LOGGER.debug("report exception", ex);
                exitCode = -12;
            } catch (ExceptionCollection ex) {
                if (ex.isFatal()) {
                    exitCode = -13;
                    LOGGER.error("One or more fatal errors occurred");
                } else {
                    exitCode = -14;
                }
                for (Throwable e : ex.getExceptions()) {
                    if (e.getMessage() != null) {
                        LOGGER.error(e.getMessage());
                        LOGGER.debug("unexpected error", e);
                    }
                }
            } finally {
                settings.cleanup();
            }
        } else {
            cli.printHelp();
        }
        return exitCode;
    }

    /**
     * Scans the specified directories and writes the dependency reports to the
     * reportDirectory.
     *
     * @param reportDirectory the path to the directory where the reports will
     * be written
     * @param outputFormats String[] of output formats of the report
     * @param applicationName the application name for the report
     * @param files the files/directories to scan
     * @param excludes the patterns for files/directories to exclude
     * @param symLinkDepth the depth that symbolic links will be followed
     * @param cvssFailScore the score to fail on if a vulnerability is found
     * @return the exit code if there was an error
     * @throws ReportException thrown when the report cannot be generated
     * @throws DatabaseException thrown when there is an error connecting to the
     * database
     * @throws ExceptionCollection thrown when an exception occurs during
     * analysis; there may be multiple exceptions contained within the
     * collection.
     */
    private int runScan(String reportDirectory, String[] outputFormats, String applicationName, String[] files,
            String[] excludes, int symLinkDepth, float cvssFailScore) throws DatabaseException,
            ExceptionCollection, ReportException {
        Engine engine = null;
        try {
            final List<String> antStylePaths = getPaths(files);
            final Set<File> paths = scanAntStylePaths(antStylePaths, symLinkDepth, excludes);

            engine = new Engine(settings);
            engine.scan(paths);

            ExceptionCollection exCol = null;
            try {
                engine.analyzeDependencies();
            } catch (ExceptionCollection ex) {
                if (ex.isFatal()) {
                    throw ex;
                }
                exCol = ex;
            }

            try {
                for (String outputFormat : outputFormats) {
                    engine.writeReports(applicationName, new File(reportDirectory), outputFormat, exCol);
                }
            } catch (ReportException ex) {
                if (exCol != null) {
                    exCol.addException(ex);
                    throw exCol;
                } else {
                    throw ex;
                }
            }
            if (exCol != null && !exCol.getExceptions().isEmpty()) {
                throw exCol;
            }
            return determineReturnCode(engine, cvssFailScore);
        } finally {
            if (engine != null) {
                engine.close();
            }
        }
    }

    /**
     * Determines the return code based on if one of the dependencies scanned
     * has a vulnerability with a CVSS score above the cvssFailScore.
     *
     * @param engine the engine used during analysis
     * @param cvssFailScore the max allowed CVSS score
     * @return returns <code>1</code> if a severe enough vulnerability is
     * identified; otherwise <code>0</code>
     */
    private int determineReturnCode(Engine engine, float cvssFailScore) {
        int retCode = 0;
        //Set the exit code based on whether we found a high enough vulnerability
        for (Dependency d : engine.getDependencies()) {
            for (Vulnerability v : d.getVulnerabilities()) {
                if ((v.getCvssV2() != null && v.getCvssV2().getScore() >= cvssFailScore)
                        || (v.getCvssV3() != null && v.getCvssV3().getBaseScore() >= cvssFailScore)
                        || (v.getUnscoredSeverity() != null && SeverityUtil.estimateCvssV2(v.getUnscoredSeverity()) >= cvssFailScore)
                        || (cvssFailScore <= 0.0f)) { //safety net to fail on any if for some reason the above misses on 0
                    retCode = 1;
                    break;
                }
            }
        }
        return retCode;
    }

    /**
     * Scans the give Ant Style paths and collects the actual files.
     *
     * @param antStylePaths a list of ant style paths to scan for actual files
     * @param symLinkDepth the depth to traverse symbolic links
     * @param excludes an array of ant style excludes
     * @return returns the set of identified files
     */
    private Set<File> scanAntStylePaths(List<String> antStylePaths, int symLinkDepth, String[] excludes) {
        final Set<File> paths = new TreeSet<>();
        for (String file : antStylePaths) {
            LOGGER.debug("Scanning {}", file);
            final DirectoryScanner scanner = new DirectoryScanner();
            String include = file.replace('\\', '/');
            final File baseDir;
            final int pos = getLastFileSeparator(include);
            final String tmpBase = include.substring(0, pos);
            final String tmpInclude = include.substring(pos + 1);
            if (tmpInclude.indexOf('*') >= 0 || tmpInclude.indexOf('?') >= 0
                    || new File(include).isFile()) {
                baseDir = new File(tmpBase);
                include = tmpInclude;
            } else {
                baseDir = new File(tmpBase, tmpInclude);
                include = "**/*";
            }
            LOGGER.debug("BaseDir: " + baseDir);
            LOGGER.debug("Include: " + include);
            scanner.setBasedir(baseDir);
            final String[] includes = {include};
            scanner.setIncludes(includes);
            scanner.setMaxLevelsOfSymlinks(symLinkDepth);
            if (symLinkDepth <= 0) {
                scanner.setFollowSymlinks(false);
            }
            if (excludes != null && excludes.length > 0) {
                for (String e : excludes) {
                    LOGGER.debug("Exclude: " + e);
                }
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
        return paths;
    }

    /**
     * Determines the ant style paths from the given array of files.
     *
     * @param files an array of file paths
     * @return a list containing ant style paths
     */
    private List<String> getPaths(String[] files) {
        final List<String> antStylePaths = new ArrayList<>();
        for (String file : files) {
            final String antPath = ensureCanonicalPath(file);
            antStylePaths.add(antPath);
        }
        return antStylePaths;
    }

    /**
     * Only executes the update phase of dependency-check.
     *
     * @throws UpdateException thrown if there is an error updating
     * @throws DatabaseException thrown if a fatal error occurred and a
     * connection to the database could not be established
     */
    private void runUpdateOnly() throws UpdateException, DatabaseException {
        try (Engine engine = new Engine(settings)) {
            engine.doUpdates();
        }
    }
    //CSOFF: MethodLength
    /**
     * Updates the global Settings.
     *
     * @param cli a reference to the CLI Parser that contains the command line
     * arguments used to set the corresponding settings in the core engine.
     * @throws InvalidSettingException thrown when a user defined properties
     * file is unable to be loaded.
     */
    protected void populateSettings(CliParser cli) throws InvalidSettingException {
        final File propertiesFile = cli.getFileArgument(CliParser.ARGUMENT.PROP);
        if (propertiesFile != null) {
            try {
                settings.mergeProperties(propertiesFile);
            } catch (FileNotFoundException ex) {
                throw new InvalidSettingException("Unable to find properties file '" + propertiesFile.getPath() + "'", ex);
            } catch (IOException ex) {
                throw new InvalidSettingException("Error reading properties file '" + propertiesFile.getPath() + "'", ex);
            }
        }
        final String dataDirectory = cli.getStringArgument(CliParser.ARGUMENT.DATA_DIRECTORY);
        if (dataDirectory != null) {
            settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        } else if (System.getProperty("basedir") != null) {
            final File dataDir = new File(System.getProperty("basedir"), "data");
            settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDir.getAbsolutePath());
        } else {
            final File jarPath = new File(App.class
                    .getProtectionDomain().getCodeSource().getLocation().getPath());
            final File base = jarPath.getParentFile();
            final String sub = settings.getString(Settings.KEYS.DATA_DIRECTORY);
            final File dataDir = new File(base, sub);
            settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDir.getAbsolutePath());
        }
        final Boolean autoUpdate = cli.hasOption(CliParser.ARGUMENT.DISABLE_AUTO_UPDATE) != null ? false : null;
        settings.setBooleanIfNotNull(Settings.KEYS.AUTO_UPDATE, autoUpdate);
        settings.setStringIfNotEmpty(Settings.KEYS.PROXY_SERVER,
                cli.getStringArgument(CliParser.ARGUMENT.PROXY_SERVER));
        settings.setStringIfNotEmpty(Settings.KEYS.PROXY_PORT,
                cli.getStringArgument(CliParser.ARGUMENT.PROXY_PORT));
        settings.setStringIfNotEmpty(Settings.KEYS.PROXY_USERNAME,
                cli.getStringArgument(CliParser.ARGUMENT.PROXY_USERNAME));
        settings.setStringIfNotEmpty(Settings.KEYS.PROXY_PASSWORD,
                cli.getStringArgument(CliParser.ARGUMENT.PROXY_PASSWORD, Settings.KEYS.PROXY_PASSWORD));
        settings.setStringIfNotEmpty(Settings.KEYS.PROXY_NON_PROXY_HOSTS,
                cli.getStringArgument(CliParser.ARGUMENT.NON_PROXY_HOSTS));
        settings.setStringIfNotEmpty(Settings.KEYS.CONNECTION_TIMEOUT,
                cli.getStringArgument(CliParser.ARGUMENT.CONNECTION_TIMEOUT));
        settings.setStringIfNotEmpty(Settings.KEYS.HINTS_FILE,
                cli.getStringArgument(CliParser.ARGUMENT.HINTS_FILE));
        settings.setIntIfNotNull(Settings.KEYS.CVE_CHECK_VALID_FOR_HOURS,
                cli.getIntegerValue(CliParser.ARGUMENT.CVE_VALID_FOR_HOURS));
        settings.setArrayIfNotEmpty(Settings.KEYS.SUPPRESSION_FILE,
                cli.getStringArguments(CliParser.ARGUMENT.SUPPRESSION_FILES));
        //File Type Analyzer Settings
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED,
                cli.hasOption(CliParser.ARGUMENT.EXPERIMENTAL));
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIRED_ENABLED,
                cli.hasOption(CliParser.ARGUMENT.RETIRED));
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_GOLANG_PATH,
                cli.getStringArgument(CliParser.ARGUMENT.PATH_TO_GO));
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_YARN_PATH,
                cli.getStringArgument(CliParser.ARGUMENT.PATH_TO_YARN));
        settings.setBooleanIfNotNull(Settings.KEYS.PRETTY_PRINT,
                cli.hasOption(CliParser.ARGUMENT.PRETTY_PRINT));
        settings.setStringIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL,
                cli.getStringArgument(CliParser.ARGUMENT.RETIREJS_URL));
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_RETIREJS_FORCEUPDATE,
                cli.hasOption(CliParser.ARGUMENT.RETIRE_JS_FORCEUPDATE));
        settings.setBoolean(Settings.KEYS.ANALYZER_JAR_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_JAR, Settings.KEYS.ANALYZER_JAR_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_MSBUILD_PROJECT_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_MSBUILD, Settings.KEYS.ANALYZER_MSBUILD_PROJECT_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_ARCHIVE, Settings.KEYS.ANALYZER_ARCHIVE_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_PY_DIST, Settings.KEYS.ANALYZER_PYTHON_DISTRIBUTION_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_PY_PKG, Settings.KEYS.ANALYZER_PYTHON_PACKAGE_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_AUTOCONF_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_AUTOCONF, Settings.KEYS.ANALYZER_AUTOCONF_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_PIP_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_PIP, Settings.KEYS.ANALYZER_PIP_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_PIPFILE_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_PIPFILE, Settings.KEYS.ANALYZER_PIPFILE_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_CMAKE_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_CMAKE, Settings.KEYS.ANALYZER_CMAKE_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_NUSPEC_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_NUSPEC, Settings.KEYS.ANALYZER_NUSPEC_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_NUGETCONF_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_NUGETCONF, Settings.KEYS.ANALYZER_NUGETCONF_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_ASSEMBLY, Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_BUNDLE_AUDIT, Settings.KEYS.ANALYZER_BUNDLE_AUDIT_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_FILE_NAME_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_FILENAME, Settings.KEYS.ANALYZER_FILE_NAME_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_MIX_AUDIT_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_MIX_AUDIT, Settings.KEYS.ANALYZER_MIX_AUDIT_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_OPENSSL_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_OPENSSL, Settings.KEYS.ANALYZER_OPENSSL_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_COMPOSER, Settings.KEYS.ANALYZER_COMPOSER_LOCK_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_CPANFILE_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_CPAN, Settings.KEYS.ANALYZER_CPANFILE_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_GOLANG_DEP_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_GO_DEP, Settings.KEYS.ANALYZER_GOLANG_DEP_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_GOLANG_MOD_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_GOLANG_MOD, Settings.KEYS.ANALYZER_GOLANG_MOD_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_NODE_JS, Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED));
        //TODO next major - remove the deprecated check in isNodeAuditDisabled
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED,
                !cli.isNodeAuditDisabled());
        settings.setBoolean(Settings.KEYS.ANALYZER_YARN_AUDIT_ENABLED,
                !cli.isYarnAuditDisabled());
        settings.setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_NODE_AUDIT_CACHE, Settings.KEYS.ANALYZER_NODE_AUDIT_USE_CACHE));
        settings.setBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_RETIRE_JS, Settings.KEYS.ANALYZER_RETIREJS_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_SWIFT, Settings.KEYS.ANALYZER_SWIFT_PACKAGE_MANAGER_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_SWIFT_PACKAGE_RESOLVED_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_SWIFT_RESOLVED, Settings.KEYS.ANALYZER_SWIFT_PACKAGE_RESOLVED_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_COCOAPODS_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_COCOAPODS, Settings.KEYS.ANALYZER_COCOAPODS_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_RUBYGEMS, Settings.KEYS.ANALYZER_RUBY_GEMSPEC_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_CENTRAL, Settings.KEYS.ANALYZER_CENTRAL_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_USE_CACHE,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_CENTRAL_CACHE, Settings.KEYS.ANALYZER_CENTRAL_USE_CACHE));
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_OSSINDEX, Settings.KEYS.ANALYZER_OSSINDEX_ENABLED));
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_USE_CACHE,
                !cli.hasDisableOption(CliParser.ARGUMENT.DISABLE_OSSINDEX_CACHE, Settings.KEYS.ANALYZER_OSSINDEX_USE_CACHE));

        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_PACKAGE_SKIPDEV,
                cli.hasOption(CliParser.ARGUMENT.NODE_PACKAGE_SKIP_DEV_DEPENDENCIES));
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NODE_AUDIT_SKIPDEV,
                cli.hasOption(CliParser.ARGUMENT.DISABLE_NODE_AUDIT_SKIPDEV));
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_NEXUS_ENABLED,
                cli.hasOption(CliParser.ARGUMENT.ENABLE_NEXUS));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_OSSINDEX_USER,
                cli.getStringArgument(CliParser.ARGUMENT.OSSINDEX_USERNAME));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_OSSINDEX_PASSWORD,
                cli.getStringArgument(CliParser.ARGUMENT.OSSINDEX_PASSWORD, Settings.KEYS.ANALYZER_OSSINDEX_PASSWORD));
        settings.setFloat(Settings.KEYS.JUNIT_FAIL_ON_CVSS,
                cli.getFloatArgument(CliParser.ARGUMENT.FAIL_JUNIT_ON_CVSS, 0));
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED,
                cli.hasOption(CliParser.ARGUMENT.ARTIFACTORY_ENABLED));
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_PARALLEL_ANALYSIS,
                cli.getBooleanArgument(CliParser.ARGUMENT.ARTIFACTORY_PARALLEL_ANALYSIS));
        settings.setBooleanIfNotNull(Settings.KEYS.ANALYZER_ARTIFACTORY_USES_PROXY,
                cli.getBooleanArgument(CliParser.ARGUMENT.ARTIFACTORY_USES_PROXY));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_ARTIFACTORY_URL,
                cli.getStringArgument(CliParser.ARGUMENT.ARTIFACTORY_URL));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME,
                cli.getStringArgument(CliParser.ARGUMENT.ARTIFACTORY_USERNAME));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN,
                cli.getStringArgument(CliParser.ARGUMENT.ARTIFACTORY_API_TOKEN));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_ARTIFACTORY_BEARER_TOKEN,
                cli.getStringArgument(CliParser.ARGUMENT.ARTIFACTORY_BEARER_TOKEN));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_MIX_AUDIT_PATH,
                cli.getStringArgument(CliParser.ARGUMENT.PATH_TO_MIX_AUDIT));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH,
                cli.getStringArgument(CliParser.ARGUMENT.PATH_TO_BUNDLE_AUDIT));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_WORKING_DIRECTORY,
                cli.getStringArgument(CliParser.ARGUMENT.PATH_TO_BUNDLE_AUDIT_WORKING_DIRECTORY));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_NEXUS_URL,
                cli.getStringArgument(CliParser.ARGUMENT.NEXUS_URL));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_NEXUS_USER,
                cli.getStringArgument(CliParser.ARGUMENT.NEXUS_USERNAME));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_NEXUS_PASSWORD,
                cli.getStringArgument(CliParser.ARGUMENT.NEXUS_PASSWORD, Settings.KEYS.ANALYZER_NEXUS_PASSWORD));
        //TODO deprecate this in favor of non-proxy host
        final boolean nexusUsesProxy = cli.isNexusUsesProxy();
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_USES_PROXY, nexusUsesProxy);
        settings.setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_NAME,
                cli.getStringArgument(CliParser.ARGUMENT.DB_DRIVER));
        settings.setStringIfNotEmpty(Settings.KEYS.DB_DRIVER_PATH,
                cli.getStringArgument(CliParser.ARGUMENT.DB_DRIVER_PATH));
        settings.setStringIfNotEmpty(Settings.KEYS.DB_CONNECTION_STRING,
                cli.getStringArgument(CliParser.ARGUMENT.CONNECTION_STRING));
        settings.setStringIfNotEmpty(Settings.KEYS.DB_USER,
                cli.getStringArgument(CliParser.ARGUMENT.DB_NAME));
        settings.setStringIfNotEmpty(Settings.KEYS.DB_PASSWORD,
                cli.getStringArgument(CliParser.ARGUMENT.DB_PASSWORD, Settings.KEYS.DB_PASSWORD));
        settings.setStringIfNotEmpty(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS,
                cli.getStringArgument(CliParser.ARGUMENT.ADDITIONAL_ZIP_EXTENSIONS));
        settings.setStringIfNotEmpty(Settings.KEYS.ANALYZER_ASSEMBLY_DOTNET_PATH,
                cli.getStringArgument(CliParser.ARGUMENT.PATH_TO_CORE));
        settings.setStringIfNotEmpty(Settings.KEYS.CVE_BASE_JSON,
                cli.getStringArgument(CliParser.ARGUMENT.CVE_BASE_URL));

        String cveModifiedJson = Optional.ofNullable(cli.getStringArgument(CliParser.ARGUMENT.CVE_MODIFIED_URL))
            .filter(arg -> !arg.isEmpty())
            .orElseGet(() -> getDefaultCveUrlModified(cli));
        settings.setStringIfNotEmpty(Settings.KEYS.CVE_MODIFIED_JSON,
                cveModifiedJson);

        settings.setStringIfNotEmpty(Settings.KEYS.CVE_USER,
                cli.getStringArgument(CliParser.ARGUMENT.CVE_USER));
        settings.setStringIfNotEmpty(Settings.KEYS.CVE_PASSWORD,
                cli.getStringArgument(CliParser.ARGUMENT.CVE_PASSWORD, Settings.KEYS.CVE_PASSWORD));
    }

    private String getDefaultCveUrlModified(CliParser cli) {
      return CveUrlParser.newInstance(settings)
          .getDefaultCveUrlModified(cli.getStringArgument(CliParser.ARGUMENT.CVE_BASE_URL));
    }

    //CSON: MethodLength
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
        final FileAppender<ILoggingEvent> fa = new FileAppender<>();
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
        rootLogger.setLevel(Level.DEBUG);
        final ThresholdFilter filter = new ThresholdFilter();
        filter.setLevel(LogLevel.INFO.getValue());
        filter.setContext(context);
        filter.start();
        rootLogger.iteratorForAppenders().forEachRemaining(action -> action.addFilter(filter));
        rootLogger.addAppender(fa);
    }

    /**
     * Takes a path and resolves it to be a canonical &amp; absolute path. The
     * caveats are that this method will take an Ant style file selector path
     * (../someDir/**\/*.jar) and convert it to an absolute/canonical path (at
     * least to the left of the first * or ?).
     *
     * @param path the path to canonicalize
     * @return the canonical path
     */
    protected String ensureCanonicalPath(String path) {
        final String basePath;
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
