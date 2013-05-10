/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
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

import java.util.EnumMap;
import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.analyzer.AnalysisException;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.AnalyzerService;
import org.owasp.dependencycheck.data.CachedWebDataSource;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.data.UpdateService;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.FileUtils;

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
    private List<Dependency> dependencies = new ArrayList<Dependency>();
    /**
     * A Map of analyzers grouped by Analysis phase.
     */
    private EnumMap<AnalysisPhase, List<Analyzer>> analyzers =
            new EnumMap<AnalysisPhase, List<Analyzer>>(AnalysisPhase.class);
    /**
     * A set of extensions supported by the analyzers.
     */
    private Set<String> extensions = new HashSet<String>();

    /**
     * Creates a new Engine.
     */
    public Engine() {
        doUpdates();
        loadAnalyzers();
    }

    /**
     * Creates a new Engine.
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

        final AnalyzerService service = AnalyzerService.getInstance();
        final Iterator<Analyzer> iterator = service.getAnalyzers();
        while (iterator.hasNext()) {
            final Analyzer a = iterator.next();
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
     * Get the dependencies identified.
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
        final File file = new File(path);
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
        final File[] files = dir.listFiles();
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
            final String msg = String.format("Path passed to scanFile(File) is not a file: %s.", file.toString());
            Logger.getLogger(Engine.class.getName()).log(Level.WARNING, msg);
        }
        final String fileName = file.getName();
        final String extension = FileUtils.getFileExtension(fileName);
        if (extension != null) {
            if (extensions.contains(extension)) {
                final Dependency dependency = new Dependency(file);
                dependencies.add(dependency);
            }
        } else {
            final String msg = String.format("No file extension found on file '%s'. The file was not analyzed.",
                    file.toString());
            Logger.getLogger(Engine.class.getName()).log(Level.FINEST, msg);
        }
    }

    /**
     * Runs the analyzers against all of the dependencies.
     */
    public void analyzeDependencies() {
        //phase one initialize
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            final List<Analyzer> analyzerList = analyzers.get(phase);
            for (Analyzer a : analyzerList) {
                try {
                    a.initialize();
                } catch (Exception ex) {
                    Logger.getLogger(Engine.class.getName()).log(Level.SEVERE,
                            "Exception occurred initializing " + a.getName() + ".", ex);
                    try {
                        a.close();
                    } catch (Exception ex1) {
                        Logger.getLogger(Engine.class.getName()).log(Level.FINER, null, ex1);
                    }
                }
            }
        }

        // analysis phases
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            final List<Analyzer> analyzerList = analyzers.get(phase);

            for (Analyzer a : analyzerList) {
                //need to create a copy of the collection because some of the
                // analyzers may modify it. This prevents ConcurrentModificationExceptions.
                final Set<Dependency> dependencySet = new HashSet<Dependency>();
                dependencySet.addAll(dependencies);
                for (Dependency d : dependencySet) {
                    if (a.supportsExtension(d.getFileExtension())) {
                        try {
                            a.analyze(d, this);
                          } catch (AnalysisException ex) {
                            d.addAnalysisException(ex);
                        }
                    }
                }
            }
        }

        //close/cleanup
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            final List<Analyzer> analyzerList = analyzers.get(phase);
            for (Analyzer a : analyzerList) {
                try {
                    a.close();
                } catch (Exception ex) {
                    Logger.getLogger(Engine.class.getName()).log(Level.WARNING, null, ex);
                }
            }
        }
    }

    /**
     * Cycles through the cached web data sources and calls update on all of them.
     */
    private void doUpdates() {
        final UpdateService service = UpdateService.getInstance();
        final Iterator<CachedWebDataSource> iterator = service.getDataSources();
        while (iterator.hasNext()) {
            final CachedWebDataSource source = iterator.next();
            try {
                source.update();
            } catch (UpdateException ex) {
                Logger.getLogger(Engine.class.getName()).log(Level.WARNING,
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
        final List<Analyzer> ret = new ArrayList<Analyzer>();
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            final List<Analyzer> analyzerList = analyzers.get(phase);
            ret.addAll(analyzerList);
        }
        return ret;
    }
}
