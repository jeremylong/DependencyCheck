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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileFilter;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.owasp.dependencycheck.exception.InitializationException;

/**
 * The base FileTypeAnalyzer that all analyzers that have specific file types
 * they analyze should extend.
 *
 * @author Jeremy Long
 */
public abstract class AbstractFileTypeAnalyzer extends AbstractAnalyzer implements FileTypeAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="Constructor">
    /**
     * Base constructor that all children must call. This checks the
     * configuration to determine if the analyzer is enabled.
     */
    public AbstractFileTypeAnalyzer() {
        reset();
    }
//</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="Field definitions">
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractFileTypeAnalyzer.class);
    /**
     * Whether the file type analyzer detected any files it needs to analyze.
     */
    private boolean filesMatched = false;

    /**
     * Get the value of filesMatched. A flag indicating whether the scan
     * included any file types this analyzer supports.
     *
     * @return the value of filesMatched
     */
    protected boolean isFilesMatched() {
        return filesMatched;
    }

    /**
     * Set the value of filesMatched. A flag indicating whether the scan
     * included any file types this analyzer supports.
     *
     * @param filesMatched new value of filesMatched
     */
    protected void setFilesMatched(boolean filesMatched) {
        this.filesMatched = filesMatched;
    }

    /**
     * A flag indicating whether or not the analyzer is enabled.
     */
    private volatile boolean enabled = true;

    /**
     * Get the value of enabled.
     *
     * @return the value of enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Set the value of enabled.
     *
     * @param enabled new value of enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
//</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="Abstract methods children must implement">
    /**
     * <p>
     * Returns the {@link java.io.FileFilter} used to determine which files are
     * to be analyzed. An example would be an analyzer that inspected Java jar
     * files. Implementors may use
     * {@link org.owasp.dependencycheck.utils.FileFilterBuilder}.</p>
     * <p>
     * If the analyzer returns null it will not cause additional files to be
     * analyzed, but will be executed against every file loaded.</p>
     *
     * @return the file filter used to determine which files are to be analyzed
     */
    protected abstract FileFilter getFileFilter();

    /**
     * Initializes the file type analyzer.
     *
     * @throws InitializationException thrown if there is an exception during
     * initialization
     */
    protected abstract void initializeFileTypeAnalyzer() throws InitializationException;

    /**
     * Analyzes a given dependency. If the dependency is an archive, such as a
     * WAR or EAR, the contents are extracted, scanned, and added to the list of
     * dependencies within the engine.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine scanning
     * @throws AnalysisException thrown if there is an analysis exception
     */
    protected abstract void analyzeFileType(Dependency dependency, Engine engine) throws AnalysisException;

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    protected abstract String getAnalyzerEnabledSettingKey();

//</editor-fold>
    //<editor-fold defaultstate="collapsed" desc="Final implementations for the Analyzer interface">
    /**
     * Initializes the analyzer.
     *
     * @throws InitializationException thrown if there is an exception during
     * initialization
     */
    @Override
    public final void initialize() throws InitializationException {
        if (filesMatched) {
            initializeFileTypeAnalyzer();
        } else {
            enabled = false;
        }
    }

    /**
     * Resets the enabled flag on the analyzer.
     */
    @Override
    public final void reset() {
        final String key = getAnalyzerEnabledSettingKey();
        try {
            enabled = Settings.getBoolean(key, true);
        } catch (InvalidSettingException ex) {
            LOGGER.warn("Invalid setting for property '{}'", key);
            LOGGER.debug("", ex);
            LOGGER.warn("{} has been disabled", getName());
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
    public final void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        if (enabled) {
            analyzeFileType(dependency, engine);
        }
    }

    @Override
    public boolean accept(File pathname) {
        final FileFilter filter = getFileFilter();
        boolean accepted = false;
        if (null == filter) {
            LOGGER.error("The '{}' analyzer is misconfigured and does not have a file filter; it will be disabled", getName());
        } else if (enabled) {
            accepted = filter.accept(pathname);
            if (accepted) {
                filesMatched = true;
            }
        }
        return accepted;
    }

    //</editor-fold>
    //<editor-fold defaultstate="collapsed" desc="Static utility methods">
    /**
     * <p>
     * Utility method to help in the creation of the extensions set. This
     * constructs a new Set that can be used in a final static declaration.</p>
     * <p>
     * This implementation was copied from
     * http://stackoverflow.com/questions/2041778/initialize-java-hashset-values-by-construction</p>
     *
     * @param strings a list of strings to add to the set.
     * @return a Set of strings.
     */
    protected static Set<String> newHashSet(String... strings) {
        final Set<String> set = new HashSet<String>(strings.length);
        Collections.addAll(set, strings);
        return set;
    }

//</editor-fold>
}
