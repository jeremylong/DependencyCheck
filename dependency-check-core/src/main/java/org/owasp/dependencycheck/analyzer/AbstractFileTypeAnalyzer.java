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

import com.hazelcast.logging.Logger;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 * The base FileTypeAnalyzer that all analyzers that have specific file types they analyze should extend.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public abstract class AbstractFileTypeAnalyzer extends AbstractAnalyzer implements FileTypeAnalyzer {

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
     * Initializes the analyzer.
     *
     * @throws Exception thrown if there is an exception during initialization
     */
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
    protected abstract void analyzeFileType(Dependency dependency, Engine engine) throws AnalysisException;

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
    public boolean supportsExtension(String extension) {
        Set<String> ext = getSupportedExtensions();
        if (ext == null) {
            String msg = String.format("The '%s%' analyzer is misconfigured and does not have any file extensions; it will be disabled", getName());
            Logger.getLogger(AbstractFileTypeAnalyzer.class.getName()).log(Level.SEVERE, msg);
            return false;
        } else {
            boolean match = ext.contains(extension);
            if (match) {
                filesMatched = match;
            }
            return match;
        }
    }
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

    private boolean enabled = true;

    /**
     * Get the value of enabled
     *
     * @return the value of enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Set the value of enabled
     *
     * @param enabled new value of enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

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
}
