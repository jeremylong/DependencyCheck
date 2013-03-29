/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import org.apache.commons.cli.ParseException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.CliParser;
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
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class App {

    /**
     * The location of the log properties configuration file.
     */
    private static final String LOG_PROPERTIES_FILE = "configuration/log.properties";

    /**
     * The main method for the application.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        prepareLogger();
        final App app = new App();
        app.run(args);
    }

    /**
     * Configures the logger for use by the application.
     */
    private static void prepareLogger() {
        //while java doc for JUL says to use preferences api - it throws an exception...
        //Preferences.systemRoot().put("java.util.logging.config.file", "log.properties");
        //System.getProperties().put("java.util.logging.config.file", "configuration/log.properties");

        //removed the file handler. since this is a console app - just write to console.
//        File dir = new File("logs");
//        if (!dir.exists()) {
//            dir.mkdir();
//        }
        try {
            final InputStream in = App.class.getClassLoader().getResourceAsStream(LOG_PROPERTIES_FILE);
            LogManager.getLogManager().reset();
            LogManager.getLogManager().readConfiguration(in);
        } catch (IOException ex) {
            System.err.println(ex.toString());
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SecurityException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
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
            Logger.getLogger(App.class.getName()).log(Level.WARNING, null, ex);
            return;
        } catch (ParseException ex) {
            System.err.println(ex.getMessage());
            cli.printHelp();
            Logger.getLogger(App.class.getName()).log(Level.INFO, null, ex);
            return;
        }

        if (cli.isGetVersion()) {
            cli.printVersionInfo();
        } else if (cli.isRunScan()) {
            runScan(cli.getReportDirectory(), cli.getReportFormat(), cli.getApplicationName(),
                    cli.getScanFiles(), cli.isAutoUpdate(), cli.isDeepScan());
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
     * @param autoUpdate whether to auto-update the cached data from the Internet
     * @param deepScan whether to perform a deep scan of the evidence in the project dependencies
     */
    private void runScan(String reportDirectory, String outputFormat, String applicationName, String[] files, boolean autoUpdate, boolean deepScan) {
        final Engine scanner = new Engine(autoUpdate);
        Settings.setBoolean(Settings.KEYS.PERFORM_DEEP_SCAN, deepScan);

        for (String file : files) {
            scanner.scan(file);
        }

        scanner.analyzeDependencies();
        final List<Dependency> dependencies = scanner.getDependencies();

        final ReportGenerator report = new ReportGenerator(applicationName, dependencies, scanner.getAnalyzers());
        try {
            report.generateReports(reportDirectory, outputFormat);
        } catch (IOException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
