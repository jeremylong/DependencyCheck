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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.Set;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 * An interface that defines an Analyzer that is used to identify Dependencies.
 * An analyzer will collect information about the dependency in the form of
 * Evidence.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public interface Analyzer {

    /**
     * Analyzes the given dependency. The analysis could be anything from
     * identifying an Identifier for the dependency, to finding vulnerabilities,
     * etc. Additionally, if the analyzer collects enough information to add a
     * description or license information for the dependency it should be added.
     *
     * @param dependency a dependency to analyze.
     * @param engine the engine that is scanning the dependencies - this is
     * useful if we need to check other dependencies
     * @throws AnalysisException is thrown if there is an error analyzing the
     * dependency file
     */
    void analyze(Dependency dependency, Engine engine) throws AnalysisException;

    /**
     * <p>Returns a list of supported file extensions. An example would be an
     * analyzer that inspected java jar files. The getSupportedExtensions
     * function would return a set with a single element "jar".</p>
     *
     * <p><b>Note:</b> when implementing this the extensions returned MUST be
     * lowercase.</p>
     *
     * @return The file extensions supported by this analyzer.
     *
     * <p>If the analyzer returns null it will not cause additional files to be
     * analyzed but will be executed against every file loaded</p>
     */
    Set<String> getSupportedExtensions();

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    String getName();

    /**
     * Returns whether or not this analyzer can process the given extension.
     *
     * @param extension the file extension to test for support.
     * @return whether or not the specified file extension is supported by this
     * analyzer.
     */
    boolean supportsExtension(String extension);

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    AnalysisPhase getAnalysisPhase();

    /**
     * The initialize method is called (once) prior to the analyze method being
     * called on all of the dependencies.
     *
     * @throws Exception is thrown if an exception occurs initializing the
     * analyzer.
     */
    void initialize() throws Exception;

    /**
     * The close method is called after all of the dependencies have been
     * analyzed.
     *
     * @throws Exception is thrown if an exception occurs closing the analyzer.
     */
    void close() throws Exception;
}
