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
     * A Map of analyzers - the key is the file extension.
     */
    protected Map<String, Analyzer> analyzers = new HashMap<String, Analyzer>();

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
        Map<String, String> associations = Settings.getPropertiesByPrefix(KEYS.FILE_EXTENSION_ANALYZER_ASSOCIATION_PREFIX);
        for (Map.Entry<String, String> entry : associations.entrySet()) {
            addAnalyzer(entry.getKey(), entry.getValue());
        }
    }

    /**
     * Adds an Analyzer to the collection of analyzers and associates the
     * analyzer with a file extension.
     *
     * If the specified class does not implement 'org.codesecure.dependencycheck.detect.Analyzer'
     * the load will fail mostly silently - only writting the failure to the log file.
     *
     * @param extension the file extension that this analyzer can analyze.
     * @param className the fully qualified classname of the Analyzer.
     */
    public final void addAnalyzer(String extension, String className) {

        ClassLoader loader = this.getClass().getClassLoader();
        try {
            Class analyzer = loader.loadClass(className);
            boolean implmnts = false;
            for (Class p : analyzer.getInterfaces()) {
                if (org.codesecure.dependencycheck.scanner.Analyzer.class.isAssignableFrom(p)) {
                    implmnts = true;
                    break;
                }
            }

            if (implmnts) {
                this.analyzers.put(extension, (Analyzer) analyzer.newInstance());
            } else {
                String msg = String.format("Class '%s' does not implement org.codesecure.dependencycheck.scanner.Analyzer and cannot be loaded as an Analyzer for extension '%s'.", className, extension);
                Logger.getLogger(Scanner.class.getName()).log(Level.WARNING, msg);
            }
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Scanner.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            Logger.getLogger(Scanner.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            Logger.getLogger(Scanner.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Get the Map of the analyzers.
     *
     * @return the analyzers loaded
     */
    public Map<String, Analyzer> getAnalyzers() {
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
            if (analyzers.containsKey(extension)) {
                Analyzer a = analyzers.get(extension);
                try {
                    Dependency dependency = a.insepct(file);
                    dependencies.add(dependency);
                } catch (IOException ex) {
                    String msg = String.format("IOException occured while scanning the file '%s'.", file.toString());
                    Logger.getLogger(Scanner.class.getName()).log(Level.SEVERE, msg, ex);
                }
            } else {
                String msg = String.format("No analyzer is configured for files of type '%s'. The file, '%s', was not analyzed.", extension, file.toString());
                Logger.getLogger(Scanner.class.getName()).log(Level.WARNING, msg);
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
