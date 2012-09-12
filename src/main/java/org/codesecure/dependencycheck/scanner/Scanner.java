package org.codesecure.dependencycheck.scanner;
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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.codesecure.dependencycheck.utils.Settings;
import org.codesecure.dependencycheck.utils.Settings.KEYS;

/**
 * Scans files, directories, etc. for Dependencies. Analyzers are loaded and
 * used to process the files found by the scanner, if a file is encountered and
 * an Analyzer is associated with the file type then the file is turned into a
 * dependency by the Analyzer.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Scanner {

    /**
     * The list of dependencies.
     */
    protected List<Dependency> dependencies = new ArrayList<Dependency>();
    /**
     * A List of analyzers.
     */
    protected List<Analyzer> analyzers = new ArrayList<Analyzer>();

    /**
     * Creates a new Scanner.
     */
    public Scanner() {
        loadAnalyzers();
    }

    /**
     * Loads the analyzers specified in the configuration file (or system properties).
     */
    private void loadAnalyzers() {
        AnalyzerService service = AnalyzerService.getInstance();
        Iterator<Analyzer> iterator = service.getAnalyzers();
        while(iterator.hasNext()) {
            Analyzer a = iterator.next();
            analyzers.add(a);
        }
    }

    /**
     * Get the List of the analyzers.
     *
     * @return the analyzers loaded
     */
    public List<Analyzer> getAnalyzers() {
        return analyzers;
    }

    /**
     * Get the dependencies identified
     *
     * @return the dependencies identified
     */
    public List<Dependency> getDependencies() {
        return dependencies;
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be
     * scanned recursively.
     * Any dependencies identified are added to the dependency collection.
     *
     * @param path the path to a file or directory to be analyzed.
     */
    public void scan(String path) {
        File file = new File(path);
        if (file.exists()) {
            if (file.isDirectory()) {
                scanDirectory(file);
            } else {
                scanFile(file);
            }
        }
    }

    /**
     * Recursively scans files and directories.
     * Any dependencies identified are added to the dependency collection.
     *
     * @param dir the directory to scan.
     */
    protected void scanDirectory(File dir) {
        File[] files = dir.listFiles();
        for (File f : files) {
            if (f.isDirectory()) {
                scanDirectory(f);
            } else {
                scanFile(f);
            }
        }
    }

    /**
     * Scans a specified file. If a dependency is identified it is added to the
     * dependency collection.
     *
     * @param file The file to scan.
     */
    protected void scanFile(File file) {
        if (!file.isFile()) {
            String msg = String.format("Path passed to scanFile(File) is not a file: %s.", file.toString());
            Logger.getLogger(Scanner.class.getName()).log(Level.WARNING, msg);
        }
        String fileName = file.getName();
        String extension = getFileExtension(fileName);
        if (extension != null) {
            for (Analyzer a : analyzers) {
                if (a.supportsExtension(extension)) {
                    try {
                        Dependency dependency = a.insepct(file);
                        if (dependency != null) {
                            dependencies.add(dependency);
                            break;
                        }
                    } catch (IOException ex) {
                        String msg = String.format("IOException occured while scanning the file '%s'.", file.toString());
                        Logger.getLogger(Scanner.class.getName()).log(Level.SEVERE, msg, ex);
                    }
                }
            }
        } else {
            String msg = String.format("No files extension found on file '%s'. The file was not analyzed.", file.toString());
            Logger.getLogger(Scanner.class.getName()).log(Level.WARNING, msg);
        }
    }

    /**
     * Returns the file extension for a specified file.
     * @param fileName the file name to retrieve the file extension from.
     * @return the file extension.
     */
    protected String getFileExtension(String fileName) {
        String ret = null;
        int pos = fileName.lastIndexOf(".");
        if (pos >= 0) {
            ret = fileName.substring(pos + 1, fileName.length());
        }
        return ret;
    }
}
