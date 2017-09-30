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
package org.owasp.dependencycheck.analyzer;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * <p>
 * An interface that defines an Analyzer that is used to identify Dependencies.
 * An analyzer will collect information about the dependency in the form of
 * Evidence.</p>
 * <p>
 * When the {@link org.owasp.dependencycheck.Engine} executes it will load the
 * analyzers and call the methods in the following order:</p>
 * <ol>
 * <li>{@link #initialize(org.owasp.dependencycheck.utils.Settings)}</li>
 * <li>{@link #prepare(org.owasp.dependencycheck.Engine)}</li>
 * <li>{@link #analyze(org.owasp.dependencycheck.dependency.Dependency, org.owasp.dependencycheck.Engine)}</li>
 * <li>{@link #close()}</li>
 * </ol>
 *
 * @author Jeremy Long
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
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    String getName();

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    AnalysisPhase getAnalysisPhase();

    /**
     * Initializes the analyzer with the configured settings.
     *
     * @param settings the configured settings
     */
    void initialize(Settings settings);

    /**
     * The prepare method is called (once) prior to the analyze method being
     * called on all of the dependencies.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException is thrown if an exception occurs
     * initializing the analyzer.
     */
    void prepare(Engine engine) throws InitializationException;

    /**
     * The close method is called after all of the dependencies have been
     * analyzed.
     *
     * @throws Exception is thrown if an exception occurs closing the analyzer.
     */
    void close() throws Exception;

    /**
     * Returns whether multiple instances of the same type of analyzer can run
     * in parallel. Note that running analyzers of different types in parallel
     * is not supported at all.
     *
     * @return {@code true} if the analyzer supports parallel processing,
     * {@code false} else
     */
    boolean supportsParallelProcessing();

    /**
     * Get the value of enabled.
     *
     * @return the value of enabled
     */
    boolean isEnabled();

}
