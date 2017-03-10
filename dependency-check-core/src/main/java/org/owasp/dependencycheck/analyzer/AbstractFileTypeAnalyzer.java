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

    //<editor-fold defaultstate="collapsed" desc="Field definitions, getters, and setters ">
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

    //</editor-fold>
    //<editor-fold defaultstate="collapsed" desc="Final implementations for the Analyzer interface">
    /**
     * Initializes the analyzer.
     *
     * @throws InitializationException thrown if there is an exception during
     * initialization
     */
    @Override
    protected final void initializeAnalyzer() throws InitializationException {
        if (filesMatched) {
            initializeFileTypeAnalyzer();
        } else {
            this.setEnabled(false);
        }
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

    //</editor-fold>
    /**
     * Determines if the file can be analyzed by the analyzer.
     *
     * @param pathname the path to the file
     * @return true if the file can be analyzed by the given analyzer; otherwise
     * false
     */
    @Override
    public boolean accept(File pathname) {
        final FileFilter filter = getFileFilter();
        boolean accepted = false;
        if (null == filter) {
            LOGGER.error("The '{}' analyzer is misconfigured and does not have a file filter; it will be disabled", getName());
        } else if (this.isEnabled()) {
            accepted = filter.accept(pathname);
            if (accepted) {
                filesMatched = true;
            }
        }
        return accepted;
    }

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
        final Set<String> set = new HashSet<>(strings.length);
        Collections.addAll(set, strings);
        return set;
    }
}
