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

import com.google.common.collect.ImmutableList;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.AnalyzerService;
import org.owasp.dependencycheck.analyzer.FileTypeAnalyzer;
import org.owasp.dependencycheck.data.nvdcve.ConnectionFactory;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.CachedWebDataSource;
import org.owasp.dependencycheck.data.update.UpdateService;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.exception.NoDataException;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import org.apache.commons.jcs.JCS;

import org.owasp.dependencycheck.exception.H2DBLockException;
import org.owasp.dependencycheck.utils.H2DBLock;

//CSOFF: AvoidStarImport
import static org.owasp.dependencycheck.analyzer.AnalysisPhase.*;
//CSON: AvoidStarImport

/**
 * Scans files, directories, etc. for Dependencies. Analyzers are loaded and
 * used to process the files found by the scan, if a file is encountered and an
 * Analyzer is associated with the file type then the file is turned into a
 * dependency.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class Engine implements FileFilter, AutoCloseable {

    /**
     * {@link Engine} execution modes.
     */
    public enum Mode {
        /**
         * In evidence collection mode the {@link Engine} only collects evidence
         * from the scan targets, and doesn't require a database.
         */
        EVIDENCE_COLLECTION(
                false,
                INITIAL,
                PRE_INFORMATION_COLLECTION,
                INFORMATION_COLLECTION,
                POST_INFORMATION_COLLECTION
        ),
        /**
         * In evidence processing mode the {@link Engine} processes the evidence
         * collected using the {@link #EVIDENCE_COLLECTION} mode. Dependencies
         * should be injected into the {@link Engine} using
         * {@link Engine#setDependencies(List)}.
         */
        EVIDENCE_PROCESSING(
                true,
                PRE_IDENTIFIER_ANALYSIS,
                IDENTIFIER_ANALYSIS,
                POST_IDENTIFIER_ANALYSIS,
                PRE_FINDING_ANALYSIS,
                FINDING_ANALYSIS,
                POST_FINDING_ANALYSIS,
                FINAL
        ),
        /**
         * In standalone mode the {@link Engine} will collect and process
         * evidence in a single execution.
         */
        STANDALONE(true, AnalysisPhase.values());

        /**
         * Whether the database is required in this mode.
         */
        private final boolean databaseRequired;
        /**
         * The analysis phases included in the mode.
         */
        private final ImmutableList<AnalysisPhase> phases;

        /**
         * Returns true if the database is required; otherwise false.
         *
         * @return whether or not the database is required
         */
        private boolean isDatabaseRequired() {
            return databaseRequired;
        }

        /**
         * Returns the phases for this mode.
         *
         * @return the phases for this mode
         */
        public ImmutableList<AnalysisPhase> getPhases() {
            return phases;
        }

        /**
         * Constructs a new mode.
         *
         * @param databaseRequired if the database is required for the mode
         * @param phases           the analysis phases to include in the mode
         */
        Mode(boolean databaseRequired, AnalysisPhase... phases) {
            this.databaseRequired = databaseRequired;
            //must use Guava 11.0.1 API as of 3/30/2019 due to Jenkins compatability issues
            //this.phases = Arrays.stream(phases).collect(ImmutableList.toImmutableList());
            this.phases = new ImmutableList.Builder<AnalysisPhase>()
                    .add(phases)
                    .build();
        }
    }

    /**
     * The list of dependencies.
     */
    private final List<Dependency> dependencies = Collections.synchronizedList(new ArrayList<>());
    /**
     * The external view of the dependency list.
     */
    private Dependency[] dependenciesExternalView = null;
    /**
     * A Map of analyzers grouped by Analysis phase.
     */
    private final Map<AnalysisPhase, List<Analyzer>> analyzers = new EnumMap<>(AnalysisPhase.class);

    /**
     * A Map of analyzers grouped by Analysis phase.
     */
    private final Set<FileTypeAnalyzer> fileTypeAnalyzers = new HashSet<>();

    /**
     * The engine execution mode indicating it will either collect evidence or
     * process evidence or both.
     */
    private final Mode mode;

    /**
     * The ClassLoader to use when dynamically loading Analyzer and Update
     * services.
     */
    private final ClassLoader serviceClassLoader;
    /**
     * A reference to the database.
     */
    private CveDB database = null;
    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Engine.class);
    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * Creates a new {@link Mode#STANDALONE} Engine.
     *
     * @param settings reference to the configured settings
     */
    public Engine(@NotNull final Settings settings) {
        this(Mode.STANDALONE, settings);
    }

    /**
     * Creates a new Engine.
     *
     * @param mode     the mode of operation
     * @param settings reference to the configured settings
     */
    public Engine(@NotNull final Mode mode, @NotNull final Settings settings) {
        this(Thread.currentThread().getContextClassLoader(), mode, settings);
    }

    /**
     * Creates a new {@link Mode#STANDALONE} Engine.
     *
     * @param serviceClassLoader a reference the class loader being used
     * @param settings           reference to the configured settings
     */
    public Engine(@NotNull final ClassLoader serviceClassLoader, @NotNull final Settings settings) {
        this(serviceClassLoader, Mode.STANDALONE, settings);
    }

    /**
     * Creates a new Engine.
     *
     * @param serviceClassLoader a reference the class loader being used
     * @param mode               the mode of the engine
     * @param settings           reference to the configured settings
     */
    public Engine(@NotNull final ClassLoader serviceClassLoader, @NotNull final Mode mode, @NotNull final Settings settings) {
        this.settings = settings;
        this.serviceClassLoader = serviceClassLoader;
        this.mode = mode;
        initializeEngine();
    }

    /**
     * Creates a new Engine using the specified classloader to dynamically load
     * Analyzer and Update services.
     *
     * @throws DatabaseException thrown if there is an error connecting to the
     *                           database
     */
    protected final void initializeEngine() {
        loadAnalyzers();
    }

    /**
     * Properly cleans up resources allocated during analysis.
     */
    @Override
    public void close() {
        if (mode.isDatabaseRequired()) {
            if (database != null) {
                database.close();
                database = null;
            }
        }
        JCS.shutdown();
    }

    /**
     * Loads the analyzers specified in the configuration file (or system
     * properties).
     */
    private void loadAnalyzers() {
        if (!analyzers.isEmpty()) {
            return;
        }
        mode.getPhases().forEach((phase) -> analyzers.put(phase, new ArrayList<>()));
        final AnalyzerService service = new AnalyzerService(serviceClassLoader, settings);
        final List<Analyzer> iterator = service.getAnalyzers(mode.getPhases());
        iterator.forEach((a) -> {
            a.initialize(this.settings);
            analyzers.get(a.getAnalysisPhase()).add(a);
            if (a instanceof FileTypeAnalyzer) {
                this.fileTypeAnalyzers.add((FileTypeAnalyzer) a);
            }
        });
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
     * Adds a dependency.
     *
     * @param dependency the dependency to add
     */
    public synchronized void addDependency(Dependency dependency) {
        dependencies.add(dependency);
        dependenciesExternalView = null;
    }

    /**
     * Sorts the dependency list.
     */
    public synchronized void sortDependencies() {
        //TODO - is this actually necassary????
//        Collections.sort(dependencies);
//        dependenciesExternalView = null;
    }

    /**
     * Removes the dependency.
     *
     * @param dependency the dependency to remove.
     */
    public synchronized void removeDependency(@NotNull final Dependency dependency) {
        dependencies.remove(dependency);
        dependenciesExternalView = null;
    }

    /**
     * Returns a copy of the dependencies as an array.
     *
     * @return the dependencies identified
     */
    @SuppressFBWarnings(justification = "This is the intended external view of the dependencies", value = {"EI_EXPOSE_REP"})
    public synchronized Dependency[] getDependencies() {
        if (dependenciesExternalView == null) {
            dependenciesExternalView = dependencies.toArray(new Dependency[0]);
        }
        return dependenciesExternalView;
    }

    /**
     * Sets the dependencies.
     *
     * @param dependencies the dependencies
     */
    public synchronized void setDependencies(@NotNull final List<Dependency> dependencies) {
        this.dependencies.clear();
        this.dependencies.addAll(dependencies);
        dependenciesExternalView = null;
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it
     * will be scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param paths an array of paths to files or directories to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.5
     */
    public List<Dependency> scan(@NotNull final String[] paths) {
        return scan(paths, null);
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it
     * will be scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param paths            an array of paths to files or directories to be analyzed
     * @param projectReference the name of the project or scope in which the
     *                         dependency was identified
     * @return the list of dependencies scanned
     * @since v1.4.4
     */
    public List<Dependency> scan(@NotNull final String[] paths, @Nullable final String projectReference) {
        final List<Dependency> deps = new ArrayList<>();
        for (String path : paths) {
            final List<Dependency> d = scan(path, projectReference);
            if (d != null) {
                deps.addAll(d);
            }
        }
        return deps;
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be
     * scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param path the path to a file or directory to be analyzed
     * @return the list of dependencies scanned
     */
    public List<Dependency> scan(@NotNull final String path) {
        return scan(path, null);
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be
     * scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param path             the path to a file or directory to be analyzed
     * @param projectReference the name of the project or scope in which the
     *                         dependency was identified
     * @return the list of dependencies scanned
     * @since v1.4.4
     */
    public List<Dependency> scan(@NotNull final String path, String projectReference) {
        final File file = new File(path);
        return scan(file, projectReference);
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it
     * will be scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param files an array of paths to files or directories to be analyzed.
     * @return the list of dependencies
     * @since v0.3.2.5
     */
    public List<Dependency> scan(File[] files) {
        return scan(files, null);
    }

    /**
     * Scans an array of files or directories. If a directory is specified, it
     * will be scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param files            an array of paths to files or directories to be analyzed.
     * @param projectReference the name of the project or scope in which the
     *                         dependency was identified
     * @return the list of dependencies
     * @since v1.4.4
     */
    public List<Dependency> scan(File[] files, String projectReference) {
        final List<Dependency> deps = new ArrayList<>();
        for (File file : files) {
            final List<Dependency> d = scan(file, projectReference);
            if (d != null) {
                deps.addAll(d);
            }
        }
        return deps;
    }

    /**
     * Scans a collection of files or directories. If a directory is specified,
     * it will be scanned recursively. Any dependencies identified are added to
     * the dependency collection.
     *
     * @param files a set of paths to files or directories to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.5
     */
    public List<Dependency> scan(Collection<File> files) {
        return scan(files, null);
    }

    /**
     * Scans a collection of files or directories. If a directory is specified,
     * it will be scanned recursively. Any dependencies identified are added to
     * the dependency collection.
     *
     * @param files            a set of paths to files or directories to be analyzed
     * @param projectReference the name of the project or scope in which the
     *                         dependency was identified
     * @return the list of dependencies scanned
     * @since v1.4.4
     */
    public List<Dependency> scan(Collection<File> files, String projectReference) {
        final List<Dependency> deps = new ArrayList<>();
        files.stream().map((file) -> scan(file, projectReference))
                .filter((d) -> (d != null))
                .forEach((d) -> deps.addAll(d));
        return deps;
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be
     * scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param file the path to a file or directory to be analyzed
     * @return the list of dependencies scanned
     * @since v0.3.2.4
     */
    public List<Dependency> scan(File file) {
        return scan(file, null);
    }

    /**
     * Scans a given file or directory. If a directory is specified, it will be
     * scanned recursively. Any dependencies identified are added to the
     * dependency collection.
     *
     * @param file             the path to a file or directory to be analyzed
     * @param projectReference the name of the project or scope in which the
     *                         dependency was identified
     * @return the list of dependencies scanned
     * @since v1.4.4
     */
    @Nullable
    public List<Dependency> scan(@NotNull final File file, String projectReference) {
        if (file.exists()) {
            if (file.isDirectory()) {
                return scanDirectory(file, projectReference);
            } else {
                final Dependency d = scanFile(file, projectReference);
                if (d != null) {
                    final List<Dependency> deps = new ArrayList<>();
                    deps.add(d);
                    return deps;
                }
            }
        }
        return null;
    }

    /**
     * Recursively scans files and directories. Any dependencies identified are
     * added to the dependency collection.
     *
     * @param dir the directory to scan
     * @return the list of Dependency objects scanned
     */
    protected List<Dependency> scanDirectory(File dir) {
        return scanDirectory(dir, null);
    }

    /**
     * Recursively scans files and directories. Any dependencies identified are
     * added to the dependency collection.
     *
     * @param dir              the directory to scan
     * @param projectReference the name of the project or scope in which the
     *                         dependency was identified
     * @return the list of Dependency objects scanned
     * @since v1.4.4
     */
    protected List<Dependency> scanDirectory(@NotNull final File dir, @Nullable final String projectReference) {
        final File[] files = dir.listFiles();
        final List<Dependency> deps = new ArrayList<>();
        if (files != null) {
            for (File f : files) {
                if (f.isDirectory()) {
                    final List<Dependency> d = scanDirectory(f, projectReference);
                    if (d != null) {
                        deps.addAll(d);
                    }
                } else {
                    final Dependency d = scanFile(f, projectReference);
                    if (d != null) {
                        deps.add(d);
                    }
                }
            }
        }
        return deps;
    }

    /**
     * Scans a specified file. If a dependency is identified it is added to the
     * dependency collection.
     *
     * @param file The file to scan
     * @return the scanned dependency
     */
    protected Dependency scanFile(@NotNull final File file) {
        return scanFile(file, null);
    }

    /**
     * Scans a specified file. If a dependency is identified it is added to the
     * dependency collection.
     *
     * @param file             The file to scan
     * @param projectReference the name of the project or scope in which the
     *                         dependency was identified
     * @return the scanned dependency
     * @since v1.4.4
     */
    protected synchronized Dependency scanFile(@NotNull final File file, @Nullable final String projectReference) {
        Dependency dependency = null;
        if (file.isFile()) {
            if (accept(file)) {
                dependency = new Dependency(file);
                if (projectReference != null) {
                    dependency.addProjectReference(projectReference);
                }
                final String sha1 = dependency.getSha1sum();
                boolean found = false;

                if (sha1 != null) {
                    for (Dependency existing : dependencies) {
                        if (sha1.equals(existing.getSha1sum())) {
                            found = true;
                            if (projectReference != null) {
                                existing.addProjectReference(projectReference);
                            }
                            if (existing.getActualFilePath() != null && dependency.getActualFilePath() != null
                                    && !existing.getActualFilePath().equals(dependency.getActualFilePath())) {
                                existing.addRelatedDependency(dependency);
                            } else {
                                dependency = existing;
                            }
                            break;
                        }
                    }
                }
                if (!found) {
                    dependencies.add(dependency);
                    dependenciesExternalView = null;
                }
            }
        } else {
            LOGGER.debug("Path passed to scanFile(File) is not a file that can be scanned by dependency-check: {}. Skipping the file.", file);
        }
        return dependency;
    }

    /**
     * Runs the analyzers against all of the dependencies. Since the mutable
     * dependencies list is exposed via {@link #getDependencies()}, this method
     * iterates over a copy of the dependencies list. Thus, the potential for
     * {@link java.util.ConcurrentModificationException}s is avoided, and
     * analyzers may safely add or remove entries from the dependencies list.
     * <p>
     * Every effort is made to complete analysis on the dependencies. In some
     * cases an exception will occur with part of the analysis being performed
     * which may not affect the entire analysis. If an exception occurs it will
     * be included in the thrown exception collection.
     *
     * @throws ExceptionCollection a collections of any exceptions that occurred
     *                             during analysis
     */
    public void analyzeDependencies() throws ExceptionCollection {
        final List<Throwable> exceptions = Collections.synchronizedList(new ArrayList<>());

        initializeAndUpdateDatabase(exceptions);

        //need to ensure that data exists
        try {
            ensureDataExists();
        } catch (NoDataException ex) {
            throwFatalExceptionCollection("Unable to continue dependency-check analysis.", ex, exceptions);
        }

        LOGGER.debug("\n----------------------------------------------------\nBEGIN ANALYSIS\n----------------------------------------------------");
        LOGGER.info("Analysis Started");
        final long analysisStart = System.currentTimeMillis();

        // analysis phases
        for (AnalysisPhase phase : mode.getPhases()) {
            final List<Analyzer> analyzerList = analyzers.get(phase);

            for (final Analyzer analyzer : analyzerList) {
                final long analyzerStart = System.currentTimeMillis();
                try {
                    initializeAnalyzer(analyzer);
                } catch (InitializationException ex) {
                    exceptions.add(ex);
                    if (ex.isFatal()) {
                        continue;
                    }
                }

                if (analyzer.isEnabled()) {
                    executeAnalysisTasks(analyzer, exceptions);

                    final long analyzerDurationMillis = System.currentTimeMillis() - analyzerStart;
                    final long analyzerDurationSeconds = TimeUnit.MILLISECONDS.toSeconds(analyzerDurationMillis);
                    LOGGER.info("Finished {} ({} seconds)", analyzer.getName(), analyzerDurationSeconds);
                } else {
                    LOGGER.debug("Skipping {} (not enabled)", analyzer.getName());
                }
            }
        }
        mode.getPhases().stream()
                .map((phase) -> analyzers.get(phase))
                .forEach((analyzerList) -> analyzerList.forEach((a) -> closeAnalyzer(a)));

        LOGGER.debug("\n----------------------------------------------------\nEND ANALYSIS\n----------------------------------------------------");
        final long analysisDurationSeconds = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() - analysisStart);
        LOGGER.info("Analysis Complete ({} seconds)", analysisDurationSeconds);
        if (exceptions.size() > 0) {
            throw new ExceptionCollection(exceptions);
        }
    }

    /**
     * Performs any necessary updates and initializes the database.
     *
     * @param exceptions a collection to store non-fatal exceptions
     * @throws ExceptionCollection thrown if fatal exceptions occur
     */
    private void initializeAndUpdateDatabase(@NotNull final List<Throwable> exceptions) throws ExceptionCollection {
        if (!mode.isDatabaseRequired()) {
            return;
        }
        final boolean autoUpdate;
        autoUpdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE, true);
        if (autoUpdate) {
            try {
                doUpdates(true);
            } catch (UpdateException ex) {
                exceptions.add(ex);
                LOGGER.warn("Unable to update 1 or more Cached Web DataSource, using local "
                        + "data instead. Results may not include recent vulnerabilities.");
                LOGGER.debug("Update Error", ex);
            } catch (DatabaseException ex) {
                throwFatalDatabaseException(ex, exceptions);
            }
        } else {
            try {
                if (ConnectionFactory.isH2Connection(settings) && !ConnectionFactory.h2DataFileExists(settings)) {
                    throw new ExceptionCollection(new NoDataException("Autoupdate is disabled and the database does not exist"), true);
                } else {
                    openDatabase(true, true);
                }
            } catch (IOException ex) {
                throw new ExceptionCollection(new DatabaseException("Autoupdate is disabled and unable to connect to the database"), true);
            } catch (DatabaseException ex) {
                throwFatalDatabaseException(ex, exceptions);
            }
        }
    }

    /**
     * Utility method to throw a fatal database exception.
     *
     * @param ex         the exception that was caught
     * @param exceptions the exception collection
     * @throws ExceptionCollection the collection of exceptions is always thrown
     *                             as a fatal exception
     */
    private void throwFatalDatabaseException(DatabaseException ex, final List<Throwable> exceptions) throws ExceptionCollection {
        final String msg;
        if (ex.getMessage().contains("Unable to connect") && ConnectionFactory.isH2Connection(settings)) {
            msg = "Unable to connect to the database - if this error persists it may be "
                    + "due to a corrupt database. Consider running `purge` to delete the existing database";
        } else {
            msg = "Unable to connect to the dependency-check database";
        }
        exceptions.add(new DatabaseException(msg, ex));
        throw new ExceptionCollection(exceptions, true);
    }

    /**
     * Executes executes the analyzer using multiple threads.
     *
     * @param exceptions a collection of exceptions that occurred during
     *                   analysis
     * @param analyzer   the analyzer to execute
     * @throws ExceptionCollection thrown if exceptions occurred during analysis
     */
    protected void executeAnalysisTasks(@NotNull final Analyzer analyzer, List<Throwable> exceptions) throws ExceptionCollection {
        LOGGER.debug("Starting {}", analyzer.getName());
        final List<AnalysisTask> analysisTasks = getAnalysisTasks(analyzer, exceptions);
        final ExecutorService executorService = getExecutorService(analyzer);

        try {
            final int timeout = settings.getInt(Settings.KEYS.ANALYSIS_TIMEOUT, 20);
            final List<Future<Void>> results = executorService.invokeAll(analysisTasks, timeout, TimeUnit.MINUTES);

            // ensure there was no exception during execution
            for (Future<Void> result : results) {
                try {
                    result.get();
                } catch (ExecutionException e) {
                    throwFatalExceptionCollection("Analysis task failed with a fatal exception.", e, exceptions);
                } catch (CancellationException e) {
                    throwFatalExceptionCollection("Analysis task was cancelled.", e, exceptions);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throwFatalExceptionCollection("Analysis has been interrupted.", e, exceptions);
        } finally {
            executorService.shutdown();
        }
    }

    /**
     * Returns the analysis tasks for the dependencies.
     *
     * @param analyzer   the analyzer to create tasks for
     * @param exceptions the collection of exceptions to collect
     * @return a collection of analysis tasks
     */
    protected synchronized List<AnalysisTask> getAnalysisTasks(Analyzer analyzer, List<Throwable> exceptions) {
        final List<AnalysisTask> result = new ArrayList<>();
        dependencies.stream().map((dependency) -> new AnalysisTask(analyzer, dependency, this, exceptions)).forEach((task) -> result.add(task));
        return result;
    }

    /**
     * Returns the executor service for a given analyzer.
     *
     * @param analyzer the analyzer to obtain an executor
     * @return the executor service
     */
    protected ExecutorService getExecutorService(Analyzer analyzer) {
        if (analyzer.supportsParallelProcessing()) {
            final int maximumNumberOfThreads = Runtime.getRuntime().availableProcessors();
            LOGGER.debug("Parallel processing with up to {} threads: {}.", maximumNumberOfThreads, analyzer.getName());
            return Executors.newFixedThreadPool(maximumNumberOfThreads);
        } else {
            LOGGER.debug("Parallel processing is not supported: {}.", analyzer.getName());
            return Executors.newSingleThreadExecutor();
        }
    }

    /**
     * Initializes the given analyzer.
     *
     * @param analyzer the analyzer to prepare
     * @throws InitializationException thrown when there is a problem
     *                                 initializing the analyzer
     */
    protected void initializeAnalyzer(@NotNull final Analyzer analyzer) throws InitializationException {
        try {
            LOGGER.debug("Initializing {}", analyzer.getName());
            analyzer.prepare(this);
        } catch (InitializationException ex) {
            LOGGER.error("Exception occurred initializing {}.", analyzer.getName());
            LOGGER.debug("", ex);
            if (ex.isFatal()) {
                try {
                    analyzer.close();
                } catch (Throwable ex1) {
                    LOGGER.trace("", ex1);
                }
            }
            throw ex;
        } catch (Throwable ex) {
            LOGGER.error("Unexpected exception occurred initializing {}.", analyzer.getName());
            LOGGER.debug("", ex);
            try {
                analyzer.close();
            } catch (Throwable ex1) {
                LOGGER.trace("", ex1);
            }
            throw new InitializationException("Unexpected Exception", ex);
        }
    }

    /**
     * Closes the given analyzer.
     *
     * @param analyzer the analyzer to close
     */
    protected void closeAnalyzer(@NotNull final Analyzer analyzer) {
        LOGGER.debug("Closing Analyzer '{}'", analyzer.getName());
        try {
            analyzer.close();
        } catch (Throwable ex) {
            LOGGER.trace("", ex);
        }
    }

    /**
     * Cycles through the cached web data sources and calls update on all of
     * them.
     *
     * @throws UpdateException   thrown if the operation fails
     * @throws DatabaseException if the operation fails due to a local database
     *                           failure
     */
    public void doUpdates() throws UpdateException, DatabaseException {
        doUpdates(false);
    }

    /**
     * Cycles through the cached web data sources and calls update on all of
     * them.
     *
     * @param remainOpen whether or not the database connection should remain
     *                   open
     * @throws UpdateException   thrown if the operation fails
     * @throws DatabaseException if the operation fails due to a local database
     *                           failure
     */
    public void doUpdates(boolean remainOpen) throws UpdateException, DatabaseException {
        if (mode.isDatabaseRequired()) {
            H2DBLock dblock = null;
            try {
                if (ConnectionFactory.isH2Connection(settings)) {
                    dblock = new H2DBLock(settings);
                    LOGGER.debug("locking for update");
                    dblock.lock();
                }
                openDatabase(false, false);
                LOGGER.info("Checking for updates");
                final long updateStart = System.currentTimeMillis();
                final UpdateService service = new UpdateService(serviceClassLoader);
                final Iterator<CachedWebDataSource> iterator = service.getDataSources();
                boolean dbUpdatesMade = false;
                UpdateException updateException = null;
                while (iterator.hasNext()) {
                    try {
                    final CachedWebDataSource source = iterator.next();
                        dbUpdatesMade |= source.update(this);
                    } catch (UpdateException ex) {
                        updateException = ex;
                        LOGGER.error(ex.getMessage());
                    }
                }
                if (dbUpdatesMade) {
                    database.defrag();
                }
                database.close();
                database = null;
                if (updateException!=null) {
                    throw updateException;
                }
                LOGGER.info("Check for updates complete ({} ms)", System.currentTimeMillis() - updateStart);
                if (remainOpen) {
                    openDatabase(true, false);
                }
            } catch (H2DBLockException ex) {
                throw new UpdateException("Unable to obtain an exclusive lock on the H2 database to perform updates", ex);
            } finally {
                if (dblock != null) {
                    dblock.release();
                }
            }
        } else {
            LOGGER.info("Skipping update check in evidence collection mode.");
        }
    }

    /**
     * <p>
     * This method is only public for unit/integration testing. This method
     * should not be called by any integration that uses
     * dependency-check-core.</p>
     * <p>
     * Opens the database connection.</p>
     *
     * @throws DatabaseException if the database connection could not be created
     */
    public void openDatabase() throws DatabaseException {
        openDatabase(false, true);
    }

    /**
     * <p>
     * This method is only public for unit/integration testing. This method
     * should not be called by any integration that uses
     * dependency-check-core.</p>
     * <p>
     * Opens the database connection; if readOnly is true a copy of the database
     * will be made.</p>
     *
     * @param readOnly     whether or not the database connection should be readonly
     * @param lockRequired whether or not a lock needs to be acquired when
     *                     opening the database
     * @throws DatabaseException if the database connection could not be created
     */
    public void openDatabase(boolean readOnly, boolean lockRequired) throws DatabaseException {
        if (mode.isDatabaseRequired() && database == null) {
            //needed to update schema any required schema changes
            database = new CveDB(settings);
            if (readOnly
                    && ConnectionFactory.isH2Connection(settings)
                    && settings.getString(Settings.KEYS.DB_CONNECTION_STRING).contains("file:%s")) {
                H2DBLock lock = null;
                try {
                    final File db = ConnectionFactory.getH2DataFile(settings);
                    if (db.isFile()) {
                        database.close();
                        if (lockRequired) {
                            lock = new H2DBLock(settings);
                            lock.lock();
                        }
                        LOGGER.debug("copying database");
                        final File temp = settings.getTempDirectory();
                        final File tempDB = new File(temp, db.getName());
                        Files.copy(db.toPath(), tempDB.toPath());
                        LOGGER.debug("copying complete '{}'", temp.toPath());
                        settings.setString(Settings.KEYS.H2_DATA_DIRECTORY, temp.getPath());
                        final String connStr = settings.getString(Settings.KEYS.DB_CONNECTION_STRING);
                        if (!connStr.contains("ACCESS_MODE_DATA")) {
                            settings.setString(Settings.KEYS.DB_CONNECTION_STRING, connStr + "ACCESS_MODE_DATA=r");
                        }
                        database = new CveDB(settings);
                    }
                } catch (IOException ex) {
                    throw new DatabaseException("Unable to open db in read only mode", ex);
                } catch (H2DBLockException ex) {
                    throw new DatabaseException("Failed to obtain lock - unable to open db in read only mode", ex);
                } finally {
                    if (lock != null) {
                        lock.release();
                    }
                }
            }
        }
    }

    /**
     * Returns a reference to the database.
     *
     * @return a reference to the database
     */
    public CveDB getDatabase() {
        return this.database;
    }

    /**
     * Returns a full list of all of the analyzers. This is useful for reporting
     * which analyzers where used.
     *
     * @return a list of Analyzers
     */
    @NotNull
    public List<Analyzer> getAnalyzers() {
        final List<Analyzer> ret = new ArrayList<>();
        //insteae of forEach - we can just do a collect
        mode.getPhases().stream().map((phase) -> analyzers.get(phase)).forEachOrdered((analyzerList) -> {
            ret.addAll(analyzerList);
        });
        return ret;
    }

    /**
     * Checks all analyzers to see if an extension is supported.
     *
     * @param file a file extension
     * @return true or false depending on whether or not the file extension is
     * supported
     */
    @Override
    public boolean accept(@Nullable final File file) {
        if (file == null) {
            return false;
        }
        /* note, we can't break early on this loop as the analyzers need to know if
        they have files to work on prior to initialization */
        return this.fileTypeAnalyzers.stream().map((a) -> a.accept(file)).reduce(false, (accumulator, result) -> accumulator || result);
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
     * Returns the configured settings.
     *
     * @return the configured settings
     */
    public Settings getSettings() {
        return settings;
    }

    /**
     * Returns the mode of the engine.
     *
     * @return the mode of the engine
     */
    public Mode getMode() {
        return mode;
    }

    /**
     * Adds a file type analyzer. This has been added solely to assist in unit
     * testing the Engine.
     *
     * @param fta the file type analyzer to add
     */
    protected void addFileTypeAnalyzer(@NotNull final FileTypeAnalyzer fta) {
        this.fileTypeAnalyzers.add(fta);
    }

    /**
     * Checks the CPE Index to ensure documents exists. If none exist a
     * NoDataException is thrown.
     *
     * @throws NoDataException thrown if no data exists in the CPE Index
     */
    private void ensureDataExists() throws NoDataException {
        if (mode.isDatabaseRequired() && (database == null || !database.dataExists())) {
            throw new NoDataException("No documents exist");
        }
    }

    /**
     * Constructs and throws a fatal exception collection.
     *
     * @param message    the exception message
     * @param throwable  the cause
     * @param exceptions a collection of exception to include
     * @throws ExceptionCollection a collection of exceptions that occurred
     *                             during analysis
     */
    private void throwFatalExceptionCollection(String message, @NotNull final Throwable throwable,
                                               @NotNull final List<Throwable> exceptions) throws ExceptionCollection {
        LOGGER.error(message);
        LOGGER.debug("", throwable);
        exceptions.add(throwable);
        throw new ExceptionCollection(exceptions, true);
    }

    /**
     * Writes the report to the given output directory.
     *
     * @param applicationName the name of the application/project
     * @param groupId         the Maven groupId
     * @param artifactId      the Maven artifactId
     * @param version         the Maven version
     * @param outputDir       the path to the output directory (can include the full
     *                        file name if the format is not ALL)
     * @param format          the report format (ALL, HTML, CSV, JSON, etc.)
     * @throws ReportException thrown if there is an error generating the report
     */
    public synchronized void writeReports(String applicationName, @Nullable final String groupId,
                                          @Nullable final String artifactId, @Nullable final String version,
                                          @NotNull final File outputDir, String format) throws ReportException {
        if (mode == Mode.EVIDENCE_COLLECTION) {
            throw new UnsupportedOperationException("Cannot generate report in evidence collection mode.");
        }
        final DatabaseProperties prop = database.getDatabaseProperties();
        final ReportGenerator r = new ReportGenerator(applicationName, groupId, artifactId, version, dependencies, getAnalyzers(), prop, settings);
        try {
            r.write(outputDir.getAbsolutePath(), format);
        } catch (ReportException ex) {
            final String msg = String.format("Error generating the report for %s", applicationName);
            throw new ReportException(msg, ex);
        }
    }

    /**
     * Writes the report to the given output directory.
     *
     * @param applicationName the name of the application/project
     * @param outputDir       the path to the output directory (can include the full
     *                        file name if the format is not ALL)
     * @param format          the report format (ALL, HTML, CSV, JSON, etc.)
     * @throws ReportException thrown if there is an error generating the report
     */
    public void writeReports(String applicationName, File outputDir, String format) throws ReportException {
        writeReports(applicationName, null, null, null, outputDir, format);
    }
}
