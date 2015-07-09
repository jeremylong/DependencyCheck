/*
 * This file is part of dependency-check-core.
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

import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.AnalyzerService;
import org.owasp.dependencycheck.analyzer.FileTypeAnalyzer;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.ConnectionFactory;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.update.CachedWebDataSource;
import org.owasp.dependencycheck.data.update.UpdateService;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.NoDataException;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Scans files, directories, etc. for Dependencies. Analyzers are loaded and used to process the files found by the scan, if a
 * file is encountered and an Analyzer is associated with the file type then the file is turned into a dependency.
 *
 * @author Jeremy Long
 */
public class Engine implements FileFilter{

    /**
     * The list of dependencies.
     */
    private List<Dependency> dependencies = new ArrayList<Dependency>();
    /**
     * A Map of analyzers grouped by Analysis phase.
     */
    private EnumMap<AnalysisPhase, List<Analyzer>> analyzers = new EnumMap<AnalysisPhase, List<Analyzer>>(AnalysisPhase.class);

    /**
     * A Map of analyzers grouped by Analysis phase.
     */
    private Set<FileTypeAnalyzer> fileTypeAnalyzers = new HashSet<FileTypeAnalyzer>();

    /**
     * The ClassLoader to use when dynamically loading Analyzer and Update services.
     */
    private ClassLoader serviceClassLoader = Thread.currentThread().getContextClassLoader();
    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Engine.class);

    /**
     * Creates a new Engine.
     *
     * @throws DatabaseException thrown if there is an error connecting to the database
     */
    public Engine() throws DatabaseException {
        initializeEngine();
    }

    /**
     * Creates a new Engine.
     *
     * @param serviceClassLoader a reference the class loader being used
     * @throws DatabaseException thrown if there is an error connecting to the database
     */
    public Engine(ClassLoader serviceClassLoader) throws DatabaseException {
        this.serviceClassLoader = serviceClassLoader;
        initializeEngine();
    }

    /**
     * Creates a new Engine using the specified classloader to dynamically load Analyzer and Update services.
     *
     * @throws DatabaseException thrown if there is an error connecting to the database
     */
    protected final void initializeEngine() throws DatabaseException {
        ConnectionFactory.initialize();
        loadAnalyzers();
    }

    /**
     * Properly cleans up resources allocated during analysis.
     */
    public void cleanup() {
        ConnectionFactory.cleanup();
    }

    /**
     * Loads the analyzers specified in the configuration file (or system properties).
     */
    private void loadAnalyzers() {
        if (!analyzers.isEmpty()) {
            return;
        }
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            analyzers.put(phase, new ArrayList<Analyzer>());
        }

        final AnalyzerService service = new AnalyzerService(serviceClassLoader);
        final Iterator<Analyzer> iterator = service.getAnalyzers();
        while (iterator.hasNext()) {
            final Analyzer a = iterator.next();
            analyzers.get(a.getAnalysisPhase()).add(a);
            if (a instanceof FileTypeAnalyzer) {
                this.fileTypeAnalyzers.add((FileTypeAnalyzer) a);
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
     * Sets the dependencies.
     *
     * @param dependencies the dependencies
     */
    public void setDependencies(List<Dependency> dependencies) {
        this.dependencies = dependencies;
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it will be scanned recursively. Any dependencies
     * identified are added to the dependency collection.
     *
     * @param paths an array of paths to files or directories to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.5
     */
    public List<Dependency> scan(String[] paths) {
        final List<Dependency> deps = new ArrayList<Dependency>();
        for (String path : paths) {
            final File file = new File(path);
            final List<Dependency> d = scan(file);
            if (d != null) {
                deps.addAll(d);
            }
        }
        return deps;
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be scanned recursively. Any dependencies identified
     * are added to the dependency collection.
     *
     * @param path the path to a file or directory to be analyzed
     * @return the list of dependencies scanned
     */
    public List<Dependency> scan(String path) {
        final File file = new File(path);
        return scan(file);
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it will be scanned recursively. Any dependencies
     * identified are added to the dependency collection.
     *
     * @param files an array of paths to files or directories to be analyzed.
     * @return the list of dependencies
     * @since v0.3.2.5
     */
    public List<Dependency> scan(File[] files) {
        final List<Dependency> deps = new ArrayList<Dependency>();
        for (File file : files) {
            final List<Dependency> d = scan(file);
            if (d != null) {
                deps.addAll(d);
            }
        }
        return deps;
    }

    /**
     * Scans a list of files or directories. If a directory is specified, it will be scanned recursively. Any dependencies
     * identified are added to the dependency collection.
     *
     * @param files a set of paths to files or directories to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.5
     */
    public List<Dependency> scan(Set<File> files) {
        final List<Dependency> deps = new ArrayList<Dependency>();
        for (File file : files) {
            final List<Dependency> d = scan(file);
            if (d != null) {
                deps.addAll(d);
            }
        }
        return deps;
    }

    /**
     * Scans a list of files or directories. If a directory is specified, it will be scanned recursively. Any dependencies
     * identified are added to the dependency collection.
     *
     * @param files a set of paths to files or directories to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.5
     */
    public List<Dependency> scan(List<File> files) {
        final List<Dependency> deps = new ArrayList<Dependency>();
        for (File file : files) {
            final List<Dependency> d = scan(file);
            if (d != null) {
                deps.addAll(d);
            }
        }
        return deps;
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be scanned recursively. Any dependencies identified
     * are added to the dependency collection.
     *
     * @param file the path to a file or directory to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.4
     */
    public List<Dependency> scan(File file) {
        if (file.exists()) {
            if (file.isDirectory()) {
                return scanDirectory(file);
            } else {
                final Dependency d = scanFile(file);
                if (d != null) {
                    final List<Dependency> deps = new ArrayList<Dependency>();
                    deps.add(d);
                    return deps;
                }
            }
        }
        return null;
    }

    /**
     * Recursively scans files and directories. Any dependencies identified are added to the dependency collection.
     *
     * @param dir the directory to scan
     * @return the list of Dependency objects scanned
     */
    protected List<Dependency> scanDirectory(File dir) {
        final File[] files = dir.listFiles();
        final List<Dependency> deps = new ArrayList<Dependency>();
        if (files != null) {
            for (File f : files) {
                if (f.isDirectory()) {
                    final List<Dependency> d = scanDirectory(f);
                    if (d != null) {
                        deps.addAll(d);
                    }
                } else {
                    final Dependency d = scanFile(f);
                    deps.add(d);
                }
            }
        }
        return deps;
    }

    /**
     * Scans a specified file. If a dependency is identified it is added to the dependency collection.
     *
     * @param file The file to scan
     * @return the scanned dependency
     */
    protected Dependency scanFile(File file) {
        if (!file.isFile()) {
            LOGGER.debug("Path passed to scanFile(File) is not a file: {}. Skipping the file.", file);
            return null;
        }
        final String fileName = file.getName();
        String extension = FileUtils.getFileExtension(fileName);
        if (null == extension) {
            extension = fileName;
        }
        Dependency dependency = null;
        if (accept(file)) {
            dependency = new Dependency(file);
            if (extension.equals(fileName)) {
                dependency.setFileExtension(extension);
            }
            dependencies.add(dependency);
        }
        return dependency;
    }

    /**
     * Runs the analyzers against all of the dependencies. Since the mutable dependencies list is exposed via
     * {@link #getDependencies()}, this method iterates over a copy of the dependencies list. Thus, the potential for
     * {@link java.util.ConcurrentModificationException}s is avoided, and analyzers may safely add or remove entries
     * from the dependencies list.
     */
    public void analyzeDependencies() {
        boolean autoUpdate = true;
        try {
            autoUpdate = Settings.getBoolean(Settings.KEYS.AUTO_UPDATE);
        } catch (InvalidSettingException ex) {
            LOGGER.debug("Invalid setting for auto-update; using true.");
        }
        if (autoUpdate) {
            doUpdates();
        }

        //need to ensure that data exists
        try {
            ensureDataExists();
        } catch (NoDataException ex) {
            LOGGER.error("{}\n\nUnable to continue dependency-check analysis.", ex.getMessage());
            LOGGER.debug("", ex);
            return;
        } catch (DatabaseException ex) {
            LOGGER.error("{}\n\nUnable to continue dependency-check analysis.", ex.getMessage());
            LOGGER.debug("", ex);
            return;

        }

        LOGGER.debug("\n----------------------------------------------------\nBEGIN ANALYSIS\n----------------------------------------------------");
        LOGGER.info("Analysis Starting");

        // analysis phases
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            final List<Analyzer> analyzerList = analyzers.get(phase);

            for (Analyzer a : analyzerList) {
                a = initializeAnalyzer(a);

                /* need to create a copy of the collection because some of the
                 * analyzers may modify it. This prevents ConcurrentModificationExceptions.
                 * This is okay for adds/deletes because it happens per analyzer.
                 */
                LOGGER.debug("Begin Analyzer '{}'", a.getName());
                final Set<Dependency> dependencySet = new HashSet<Dependency>();
                dependencySet.addAll(dependencies);
                for (Dependency d : dependencySet) {
                    boolean shouldAnalyze = true;
                    if (a instanceof FileTypeAnalyzer) {
                        final FileTypeAnalyzer fAnalyzer = (FileTypeAnalyzer) a;
                        shouldAnalyze = fAnalyzer.accept(d.getActualFile());
                    }
                    if (shouldAnalyze) {
                        LOGGER.debug("Begin Analysis of '{}'", d.getActualFilePath());
                        try {
                            a.analyze(d, this);
                        } catch (AnalysisException ex) {
                            LOGGER.warn("An error occurred while analyzing '{}'.", d.getActualFilePath());
                            LOGGER.debug("", ex);
                        } catch (Throwable ex) {
                            //final AnalysisException ax = new AnalysisException(axMsg, ex);
                            LOGGER.warn("An unexpected error occurred during analysis of '{}'", d.getActualFilePath());
                            LOGGER.debug("", ex);
                        }
                    }
                }
            }
        }
        for (AnalysisPhase phase : AnalysisPhase.values()) {
            final List<Analyzer> analyzerList = analyzers.get(phase);

            for (Analyzer a : analyzerList) {
                closeAnalyzer(a);
            }
        }

        LOGGER.debug("\n----------------------------------------------------\nEND ANALYSIS\n----------------------------------------------------");
        LOGGER.info("Analysis Complete");
    }

    /**
     * Initializes the given analyzer.
     *
     * @param analyzer the analyzer to initialize
     * @return the initialized analyzer
     */
    protected Analyzer initializeAnalyzer(Analyzer analyzer) {
        try {
            LOGGER.debug("Initializing {}", analyzer.getName());
            analyzer.initialize();
        } catch (Throwable ex) {
            LOGGER.error("Exception occurred initializing {}.", analyzer.getName());
            LOGGER.debug("", ex);
            try {
                analyzer.close();
            } catch (Throwable ex1) {
                LOGGER.trace("", ex1);
            }
        }
        return analyzer;
    }

    /**
     * Closes the given analyzer.
     *
     * @param analyzer the analyzer to close
     */
    protected void closeAnalyzer(Analyzer analyzer) {
        LOGGER.debug("Closing Analyzer '{}'", analyzer.getName());
        try {
            analyzer.close();
        } catch (Throwable ex) {
            LOGGER.trace("", ex);
        }
    }

    /**
     * Cycles through the cached web data sources and calls update on all of them.
     */
    public void doUpdates() {
        LOGGER.info("Checking for updates");
        final UpdateService service = new UpdateService(serviceClassLoader);
        final Iterator<CachedWebDataSource> iterator = service.getDataSources();
        while (iterator.hasNext()) {
            final CachedWebDataSource source = iterator.next();
            try {
                source.update();
            } catch (UpdateException ex) {
                LOGGER.warn(
                        "Unable to update Cached Web DataSource, using local data instead. Results may not include recent vulnerabilities.");
                LOGGER.debug("Unable to update details for {}", source.getClass().getName(), ex);
            }
        }
        LOGGER.info("Check for updates complete");
    }

    /**
     * Returns a full list of all of the analyzers. This is useful for reporting which analyzers where used.
     *
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

    /**
     * Checks all analyzers to see if an extension is supported.
     *
     * @param file a file extension
     * @return true or false depending on whether or not the file extension is supported
     */
    public boolean accept(File file) {
        if (file == null) {
            return false;
        }
        boolean scan = false;
        for (FileTypeAnalyzer a : this.fileTypeAnalyzers) {
            /* note, we can't break early on this loop as the analyzers need to know if
             they have files to work on prior to initialization */
            scan |= a.accept(file);
        }
        return scan;
    }

    /**
     * Returns the set of file type analyzers.
     *
     * @return the set of file type analyzers
     */
    public Set<FileTypeAnalyzer> getFileTypeAnalyzers() {
        return this.fileTypeAnalyzers;
    }

    /**
     * Checks the CPE Index to ensure documents exists. If none exist a NoDataException is thrown.
     *
     * @throws NoDataException   thrown if no data exists in the CPE Index
     * @throws DatabaseException thrown if there is an exception opening the database
     */
    private void ensureDataExists() throws NoDataException, DatabaseException {
        final CveDB cve = new CveDB();
        try {
            cve.open();
            if (!cve.dataExists()) {
                throw new NoDataException("No documents exist");
            }
        } catch (DatabaseException ex) {
            throw new NoDataException(ex.getMessage(), ex);
        } finally {
            cve.close();
        }
    }
}
