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
package org.codesecure.dependencycheck;

import java.util.EnumMap;
import org.codesecure.dependencycheck.dependency.Dependency;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.codesecure.dependencycheck.analyzer.AnalysisException;
import org.codesecure.dependencycheck.analyzer.AnalysisPhase;
import org.codesecure.dependencycheck.analyzer.Analyzer;
import org.codesecure.dependencycheck.analyzer.AnalyzerService;
import org.codesecure.dependencycheck.analyzer.ArchiveAnalyzer;
import org.codesecure.dependencycheck.data.CachedWebDataSource;
import org.codesecure.dependencycheck.data.UpdateException;
import org.codesecure.dependencycheck.data.UpdateService;
import org.codesecure.dependencycheck.utils.FileUtils;

/**
 * Scans files, directories, etc. for Dependencies. Analyzers are loaded and
 * used to process the files found by the scan, if a file is encountered and an
 * Analyzer is associated with the file type then the file is turned into a
 * dependency.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Engine {

    /**
     * The list of dependencies.
     */
    protected List<Dependency> dependencies = new ArrayList<Dependency>();
    /**
     * A Map of analyzers grouped by Analysis phase.
     */
    protected EnumMap<AnalysisPhase, List<Analyzer>> analyzers =
            new EnumMap<AnalysisPhase, List<Analyzer>>(AnalysisPhase.class);
    /**
     * A set of extensions supported by the analyzers.
     */
    protected Set<String> extensions = new HashSet<String>();

    /**
     * Creates a new Engine.
     */
    public Engine() {
        doUpdates();
        loadAnalyzers();
    }

    /**
     * Creates a new Engine
     *
     * @param autoUpdate indicates whether or not data should be updated from
     * the Internet.
     */
    public Engine(boolean autoUpdate) {
        if (autoUpdate) {
            doUpdates();
        }
        loadAnalyzers();
    }

    /**
     * Loads the analyzers specified in the configuration file (or system
     * properties).
     */
    private void loadAnalyzers() {

        for (AnalysisPhase phase : AnalysisPhase.values()) {
            analyzers.put(phase, new ArrayList<Analyzer>());
        }

        AnalyzerService service = AnalyzerService.getInstance();
        Iterator<Analyzer> iterator = service.getAnalyzers();
        while (iterator.hasNext()) {
            Analyzer a = iterator.next();
            analyzers.get(a.getAnalysisPhase()).add(a);
            if (a.getSupportedExtensions() != null) {
                extensions.addAll(a.getSupportedExtensions());
            }
        }
    }

    /**
     * Get the List of the analyzers for a specific phase of analysis.
     *
     * @param phase the phase to get the configured analyzers.
     * @return the analyzers loaded
     */
    public List<Analyzer> getAnalyzers(AnalysisPhase phase) {
        return analyzers.get(phase);
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
     * scanned recursively. Any dependencies identified are added to the
     * dependency collection.
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
     * Recursively scans files and directories. Any dependencies identified are
     * added to the dependency collection.
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
            Logger.getLogger(Engine.class.getName()).log(Level.WARNING, msg);
        }
        String fileName = file.getName();
        String extension = FileUtils.getFileExtension(fileName);
        if (extension != null) {
            if (extensions.contains(extension)) {
                Dependency dependency = new Dependency(file);
                dependencies.add(dependency);
            }
        } else {
            String msg = String.format("No file extension found on file '%s'. The file was not analyzed.",
                    file.toString());
            Logger.getLogger(Engine.class.getName()).log(Level.FINEST, msg);
        }
    }

    /**
     * Runs the analyzers against all of the dependencies.
     */
    public void analyzeDependencies() {
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            List<Analyzer> analyzerList = analyzers.get(phase);

            for (Analyzer a : analyzerList) {
                try {
                    a.initialize();
                } catch (Exception ex) {
                    Logger.getLogger(Engine.class.getName()).log(Level.SEVERE,
                            "Exception occured initializing " + a.getName() + ".", ex);
                    try {
                        a.close();
                    } catch (Exception ex1) {
                        Logger.getLogger(Engine.class.getName()).log(Level.FINER, null, ex1);
                    }
                    continue;
                }
                for (Dependency d : dependencies) {
                    if (a.supportsExtension(d.getFileExtension())) {
                        try {
                            if (a instanceof ArchiveAnalyzer) {
                                ArchiveAnalyzer aa = (ArchiveAnalyzer) a;
                                aa.analyze(d, this);
                            } else {
                                a.analyze(d);
                            }
                        } catch (AnalysisException ex) {
                            d.addAnalysisException(ex);
                        } catch (IOException ex) {
                            String msg = String.format("IOException occured while analyzing the file '%s'.",
                                    d.getActualFilePath());
                            Logger.getLogger(Engine.class.getName()).log(Level.SEVERE, msg, ex);
                        }
                    }
                }
                try {
                    a.close();
                } catch (Exception ex) {
                    Logger.getLogger(Engine.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

        //Now cycle through all of the analyzers one last time to call
        // cleanup on any archiveanalyzers. These should only exist in the
        // initial phase, but we are going to be thourough just in case.
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            List<Analyzer> analyzerList = analyzers.get(phase);
            for (Analyzer a : analyzerList) {
                if (a instanceof ArchiveAnalyzer) {
                    ArchiveAnalyzer aa = (ArchiveAnalyzer) a;
                    aa.cleanup();
                }
            }
        }
    }

    /**
     *
     */
    private void doUpdates() {
        UpdateService service = UpdateService.getInstance();
        Iterator<CachedWebDataSource> iterator = service.getDataSources();
        while (iterator.hasNext()) {
            CachedWebDataSource source = iterator.next();
            try {
                source.update();
            } catch (UpdateException ex) {
                Logger.getLogger(Engine.class.getName()).log(Level.SEVERE,
                        "Unable to update " + source.getClass().getName(), ex);
            }
        }
    }

    /**
     * Returns a full list of all of the analyzers. This is useful
     * for reporting which analyzers where used.
     * @return a list of Analyzers
     */
    public List<Analyzer> getAnalyzers() {
        List<Analyzer> ret = new ArrayList<Analyzer>();
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            List<Analyzer> analyzerList = analyzers.get(phase);
            ret.addAll(analyzerList);
        }
        return ret;
    }
}
