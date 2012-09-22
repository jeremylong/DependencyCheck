package org.codesecure.dependencycheck;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.cli.ParseException;
import org.codesecure.dependencycheck.data.cpe.CPEQuery;
import org.codesecure.dependencycheck.data.cpe.Index;
import org.codesecure.dependencycheck.data.cpe.xml.Importer;
import org.codesecure.dependencycheck.reporting.ReportGenerator;
import org.codesecure.dependencycheck.dependency.Dependency;
import org.codesecure.dependencycheck.utils.CliParser;
import org.xml.sax.SAXException;

/*
 * This file is part of App.
 *
 * App is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * App is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with App. If not, see http://www.gnu.org/licenses/.
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
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        //Preferences.systemRoot().put("java.util.logging.config.file", "log.properties");
        App app = new App();
        app.run(args);
    }

    /**
     * main CLI entry-point into the application.
     *
     * @param args the command line arguments
     */
    public void run(String[] args) {
        CliParser cli = new CliParser();
        try {
            cli.parse(args);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
            return;
        } catch (ParseException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
            return;
        }

        if (cli.isGetVersion()) {
            cli.printVersionInfo();
        } else if (cli.isLoadCPE()) {
            loadCPE(cli.getCpeFile());
        } else if (cli.isRunScan()) {
            if (cli.isAutoUpdate()) {
                Index cpeI = new Index();
                try {
                    cpeI.update();
                } catch (Exception ex) {
                    Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            runScan(cli.getReportDirectory(), cli.getApplicationName(), cli.getScanFiles());
        } else {
            cli.printHelp();
        }

    }

    /**
     * Loads the specified CPE.XML file into Lucene Index.
     * @param cpePath
     */
    private void loadCPE(String cpePath) {
        try {
            Importer.importXML(cpePath);
        } catch (ParserConfigurationException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SAXException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Scans the specified directories and writes the dependency reports to the reportDirectory.
     * @param reportDirectory the path to the directory where the reports will be written.
     * @param applicationName the application name for the report.
     * @param files the files/directories to scan.
     */
    private void runScan(String reportDirectory, String applicationName, String[] files) {
        try {
            Engine scanner = new Engine();
            for (String file : files) {
                scanner.scan(file);
            }
            scanner.analyzeDependencies();
            List<Dependency> dependencies = scanner.getDependencies();
            CPEQuery query = new CPEQuery();
            query.open();
            for (Dependency d : dependencies) {
                query.determineCPE(d);
            }
            query.close();
            ReportGenerator report = new ReportGenerator();
            try {
                report.generateReports(reportDirectory, applicationName, dependencies);
            } catch (IOException ex) {
                Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
            }

        } catch (IOException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        } catch (org.apache.lucene.queryParser.ParseException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
