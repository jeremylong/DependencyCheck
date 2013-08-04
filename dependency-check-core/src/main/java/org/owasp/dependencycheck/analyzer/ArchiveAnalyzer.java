/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.ExtractionException;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * <p>An analyzer that works on archive files:
 * <ul>
 * <li><b>ZIP</b> - if it is determined to be a JAR, WAR or EAR a copy is made
 * and the copy is given the correct extension so that it will be correctly
 * analyzed.</li>
 * <li><b>WAR</b> - the WAR contents are extracted and added as dependencies to
 * the scan. The displayed path is relative to the WAR.</li>
 * <li><b>EAR</b> - the WAR contents are extracted and added as dependencies to
 * the scan. Any WAR files are also processed so that the contained JAR files
 * are added to the list of dependencies. The displayed path is relative to the
 * EAR.</li>
 * </ul></p>
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class ArchiveAnalyzer extends AbstractAnalyzer implements Analyzer {

    /**
     * The count of directories created during analysis. This is used for
     * creating temporary directories.
     */
    private static int dirCount = 0;
    /**
     * The parent directory for the individual directories per archive.
     */
    private File tempFileLocation = null;
    /**
     * The max scan depth that the analyzer will recursively extract nested
     * archives.
     */
    private static final int MAX_SCAN_DEPTH = Settings.getInt("archive.scan.depth", 3);
    /**
     * Tracks the current scan/extraction depth for nested archives.
     */
    private int scanDepth = 0;
    //<editor-fold defaultstate="collapsed" desc="All standard implmentation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Archive Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INITIAL;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final Set<String> EXTENSIONS = newHashSet("zip", "ear", "war");

    /**
     * Returns a list of file EXTENSIONS supported by this analyzer.
     *
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    public Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns whether or not this analyzer can process the given extension.
     *
     * @param extension the file extension to test for support.
     * @return whether or not the specified file extension is supported by this
     * analyzer.
     */
    public boolean supportsExtension(String extension) {
        return EXTENSIONS.contains(extension);
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }
    //</editor-fold>

    /**
     * The initialize method does nothing for this Analyzer.
     *
     * @throws Exception is thrown if there is an exception deleting or creating
     * temporary files
     */
    @Override
    public void initialize() throws Exception {
        final String tmpDir = Settings.getString(Settings.KEYS.TEMP_DIRECTORY, System.getProperty("java.io.tmpdir"));
        final File baseDir = new File(tmpDir);
        tempFileLocation = File.createTempFile("check", "tmp", baseDir);
        if (!tempFileLocation.delete()) {
            throw new AnalysisException("Unable to delete temporary file '" + tempFileLocation.getAbsolutePath() + "'.");
        }
        if (!tempFileLocation.mkdirs()) {
            throw new AnalysisException("Unable to create directory '" + tempFileLocation.getAbsolutePath() + "'.");
        }
    }

    /**
     * The close method does nothing for this Analyzer.
     *
     * @throws Exception thrown if there is an exception deleting temporary
     * files
     */
    @Override
    public void close() throws Exception {
        if (tempFileLocation != null && tempFileLocation.exists()) {
            FileUtils.delete(tempFileLocation, true);
        }
    }

    /**
     * Analyzes a given dependency. If the dependency is an archive, such as a
     * WAR or EAR, the contents are extracted, scanned, and added to the list of
     * dependencies within the engine.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine scanning
     * @throws AnalysisException thrown if there is an analysis exception
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        final File f = new File(dependency.getActualFilePath());
        final File tmpDir = getNextTempDirectory();
        try {
            org.owasp.dependencycheck.utils.FileUtils.extractFiles(f, tmpDir, engine);
        } catch (ExtractionException ex) {
            final String msg = String.format("Unable to extract files from '%s'; this file is being skipped.", dependency.getActualFilePath());
            throw new AnalysisException(msg, ex);
        }

        //make a copy
        final List<Dependency> dependencies = new ArrayList<Dependency>(engine.getDependencies());
        engine.scan(tmpDir);
        final List<Dependency> newDependencies = engine.getDependencies();
        if (dependencies.size() != newDependencies.size()) {
            //get the new dependencies
            final Set<Dependency> dependencySet = new HashSet<Dependency>();
            dependencySet.addAll(newDependencies);
            dependencySet.removeAll(dependencies);

            for (Dependency d : dependencySet) {
                //fix the dependency's display name and path
                final String displayPath = String.format("%s%s",
                        dependency.getFilePath(),
                        d.getActualFilePath().substring(tmpDir.getAbsolutePath().length()));
                final String displayName = String.format("%s%s%s",
                        dependency.getFileName(),
                        File.separator,
                        d.getFileName());
                d.setFilePath(displayPath);
                d.setFileName(displayName);

                //TODO - can we get more evidence from the parent? EAR contains module name, etc.

                //analyze the dependency (i.e. extract files) if it is a supported type.
                if (this.supportsExtension(d.getFileExtension()) && scanDepth < MAX_SCAN_DEPTH) {
                    scanDepth += 1;
                    analyze(d, engine);
                    scanDepth -= 1;
                }
            }
        }
        Collections.sort(engine.getDependencies());
    }

    /**
     * Retrieves the next temporary directory to extract an archive too.
     *
     * @return a directory
     * @throws AnalysisException thrown if unable to create temporary directory
     */
    private File getNextTempDirectory() throws AnalysisException {
        dirCount += 1;
        final File directory = new File(tempFileLocation, String.valueOf(dirCount));
        if (!directory.mkdirs()) {
            throw new AnalysisException("Unable to create temp directory '" + directory.getAbsolutePath() + "'.");
        }
        return directory;
    }
}
