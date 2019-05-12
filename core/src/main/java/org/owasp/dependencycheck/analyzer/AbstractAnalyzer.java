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

import javax.annotation.concurrent.ThreadSafe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for analyzers to avoid code duplication of prepare and close as
 * most analyzers do not need these methods.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public abstract class AbstractAnalyzer implements Analyzer {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractAnalyzer.class);
    /**
     * A flag indicating whether or not the analyzer is enabled.
     */
    private volatile boolean enabled = true;
    /**
     * The configured settings.
     */
    private Settings settings;

    /**
     * Get the value of enabled.
     *
     * @return the value of enabled
     */
    @Override
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

    /**
     * Returns the configured settings.
     *
     * @return the configured settings
     */
    protected Settings getSettings() {
        return settings;
    }

    /**
     * Initializes the analyzer with the configured settings.
     *
     * @param settings the configured settings to use
     */
    @Override
    public void initialize(Settings settings) {
        this.settings = settings;
        final String key = getAnalyzerEnabledSettingKey();
        this.setEnabled(settings.getBoolean(key, true));
    }

    /**
     * Initialize the abstract analyzer.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if there is an exception
     */
    @Override
    public final void prepare(Engine engine) throws InitializationException {
        if (isEnabled()) {
            prepareAnalyzer(engine);
        } else {
            LOGGER.debug("{} has been disabled", getName());
        }
    }

    /**
     * Prepares a given Analyzer. This will be skipped if the analyzer is
     * disabled.
     *
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException thrown if there is an exception
     */
    protected void prepareAnalyzer(Engine engine) throws InitializationException {
        // Intentionally empty, analyzer will override this if they must prepare anything.
    }

    /**
     * Analyzes a given dependency. If the dependency is an archive, such as a
     * WAR or EAR, the contents are extracted, scanned, and added to the list of
     * dependencies within the engine.
     *
     * @param dependency the dependency to analyze
     * @param engine     the engine scanning
     * @throws AnalysisException thrown if there is an analysis exception
     */
    @Override
    public final void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        if (this.isEnabled()) {
            analyzeDependency(dependency, engine);
        }
    }

    /**
     * Analyzes a given dependency. If the dependency is an archive, such as a
     * WAR or EAR, the contents are extracted, scanned, and added to the list of
     * dependencies within the engine.
     *
     * @param dependency the dependency to analyze
     * @param engine     the engine scanning
     * @throws AnalysisException thrown if there is an analysis exception
     */
    protected abstract void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException;

    /**
     * The close method does nothing for this Analyzer.
     *
     * @throws Exception thrown if there is an exception
     */
    @Override
    public final void close() throws Exception {
        if (isEnabled()) {
            closeAnalyzer();
        }
    }

    /**
     * Closes a given Analyzer. This will be skipped if the analyzer is
     * disabled.
     *
     * @throws Exception thrown if there is an exception
     */
    protected void closeAnalyzer() throws Exception {
        // Intentionally empty, analyzer will override this if they must close a resource.
    }

    /**
     * The default is to support parallel processing.
     *
     * @return true
     */
    @Override
    public boolean supportsParallelProcessing() {
        return true;
    }

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    protected abstract String getAnalyzerEnabledSettingKey();

}
