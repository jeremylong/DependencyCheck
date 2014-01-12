/*
 * This file is part of dependency-check-cli.
 *
 * Dependency-check-cli is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-cli is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-cli. If not, see http://www.gnu.org/licenses/.
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
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.cli.CliParser;
import org.owasp.dependencycheck.utils.LogUtils;
import org.owasp.dependencycheck.utils.Settings;

/*
 * This file is part of App.
 *
 * App is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * App is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * App. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
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
            updateSettings(cli.isAutoUpdate(), cli.getConnectionTimeout(), cli.getProxyUrl(),
                    cli.getProxyPort(), cli.getProxyUsername(), cli.getProxyPassword(),
                    cli.getDataDirectory(), cli.getPropertiesFile(), cli.getSuppressionFile());
            runScan(cli.getReportDirectory(), cli.getReportFormat(), cli.getApplicationName(), cli.getScanFiles());
        } else {
            cli.printHelp();
        }
    }

    /**
     * Scans the specified directories and writes the dependency reports to the
     * reportDirectory.
     *
     * @param reportDirectory the path to the directory where the reports will
     * be written
     * @param outputFormat the output format of the report
     * @param applicationName the application name for the report
     * @param files the files/directories to scan
     */
    private void runScan(String reportDirectory, String outputFormat, String applicationName, String[] files) {
        final Engine scanner = new Engine();

        for (String file : files) {
            scanner.scan(file);
        }

        scanner.analyzeDependencies();
        final List<Dependency> dependencies = scanner.getDependencies();

        final ReportGenerator report = new ReportGenerator(applicationName, dependencies, scanner.getAnalyzers());
        try {
            report.generateReports(reportDirectory, outputFormat);
        } catch (IOException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, "There was an IO error while attempting to generate the report.");
            Logger.getLogger(App.class.getName()).log(Level.INFO, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, "There was an error while attempting to generate the report.");
            Logger.getLogger(App.class.getName()).log(Level.INFO, null, ex);
        }
    }

    /**
     * Updates the global Settings.
     *
     * @param autoUpdate whether or not to update cached web data sources
     * @param connectionTimeout the timeout to use when downloading resources
     * (null or blank will use default)
     * @param proxyUrl the proxy url (null or blank means no proxy will be used)
     * @param proxyPort the proxy port (null or blank means no port will be
     * used)
     * @param proxyUser the proxy user name
     * @param proxyPass the password for the proxy
     * @param dataDirectory the directory to store/retrieve persistent data from
     * @param propertiesFile the properties file to utilize
     * @param suppressionFile the path to the suppression file
     */
    private void updateSettings(boolean autoUpdate, String connectionTimeout, String proxyUrl, String proxyPort,
            String proxyUser, String proxyPass, String dataDirectory, File propertiesFile,
            String suppressionFile) {

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
    }
}
