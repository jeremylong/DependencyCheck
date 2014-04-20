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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * The base FileTypeAnalyzer that all analyzers that have specific file types they analyze should extend.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public abstract class AbstractFileTypeAnalyzer extends AbstractAnalyzer implements FileTypeAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="Constructor">
    /**
     * Base constructor that all children must call. This checks the configuration to determine if the analyzer is
     * enabled.
     */
    public AbstractFileTypeAnalyzer() {
        final String key = getAnalyzerEnabledSettingKey();
        try {
            enabled = Settings.getBoolean(key, true);
        } catch (InvalidSettingException ex) {
            String msg = String.format("Invalid settting for property '%s'", key);
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, "", ex);
            msg = String.format("%s has been disabled", getName());
            LOGGER.log(Level.WARNING, msg);
        }
    }
//</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="Field defentitions">
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractFileTypeAnalyzer.class.getName());
    /**
     * Whether the file type analyzer detected any files it needs to analyze.
     */
    private boolean filesMatched = false;

    /**
     * Get the value of filesMatched. A flag indicating whether the scan included any file types this analyzer supports.
     *
     * @return the value of filesMatched
     */
    protected boolean isFilesMatched() {
        return filesMatched;
    }

    /**
     * Set the value of filesMatched. A flag indicating whether the scan included any file types this analyzer supports.
     *
     * @param filesMatched new value of filesMatched
     */
    protected void setFilesMatched(boolean filesMatched) {
        this.filesMatched = filesMatched;
    }

    /**
     * A flag indicating whether or not the analyzer is enabled.
     */
    private boolean enabled = true;

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
     * Returns a list of supported file extensions. An example would be an analyzer that inspected java jar files. The
     * getSupportedExtensions function would return a set with a single element "jar".</p>
     *
     * <p>
     * <b>Note:</b> when implementing this the extensions returned MUST be lowercase.</p>
     *
     * @return The file extensions supported by this analyzer.
     *
     * <p>
     * If the analyzer returns null it will not cause additional files to be analyzed but will be executed against every
     * file loaded</p>
     */
    protected abstract Set<String> getSupportedExtensions();

    /**
     * Initializes the file type analyzer.
     *
     * @throws Exception thrown if there is an exception during initialization
     */
    protected abstract void initializeFileTypeAnalyzer() throws Exception;

    /**
     * Analyzes a given dependency. If the dependency is an archive, such as a WAR or EAR, the contents are extracted,
     * scanned, and added to the list of dependencies within the engine.
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
     * @throws Exception thrown if there is an exception during initialization
     */
    @Override
    public final void initialize() throws Exception {
        if (filesMatched) {
            initializeFileTypeAnalyzer();
        } else {
            enabled = false;
        }
    }

    /**
     * Analyzes a given dependency. If the dependency is an archive, such as a WAR or EAR, the contents are extracted,
     * scanned, and added to the list of dependencies within the engine.
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

    /**
     * Returns whether or not this analyzer can process the given extension.
     *
     * @param extension the file extension to test for support.
     * @return whether or not the specified file extension is supported by this analyzer.
     */
    @Override
    public final boolean supportsExtension(String extension) {
        if (!enabled) {
            return false;
        }
        final Set<String> ext = getSupportedExtensions();
        if (ext == null) {
            final String msg = String.format("The '%s' analyzer is misconfigured and does not have any file extensions;"
                    + " it will be disabled", getName());
            LOGGER.log(Level.SEVERE, msg);
            return false;
        } else {
            final boolean match = ext.contains(extension);
            if (match) {
                filesMatched = match;
            }
            return match;
        }
    }
//</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="Static utility methods">
    /**
     * <p>
     * Utility method to help in the creation of the extensions set. This constructs a new Set that can be used in a
     * final static declaration.</p>
     *
     * <p>
     * This implementation was copied from
     * http://stackoverflow.com/questions/2041778/initialize-java-hashset-values-by-construction</p>
     *
     * @param strings a list of strings to add to the set.
     * @return a Set of strings.
     */
    protected static Set<String> newHashSet(String... strings) {
        final Set<String> set = new HashSet<String>();

        Collections.addAll(set, strings);
        return set;
    }
//</editor-fold>
}
