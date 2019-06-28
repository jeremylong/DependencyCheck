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

import java.util.ArrayList;

import org.slf4j.LoggerFactory;

import static java.util.Arrays.asList;

import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;
import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.utils.Settings;

/**
 * The Analyzer Service Loader. This class loads all services that implement
 * {@link org.owasp.dependencycheck.analyzer.Analyzer}.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class AnalyzerService {

    /**
     * The Logger for use throughout the class.
     */
    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(AnalyzerService.class);

    /**
     * The service loader for analyzers.
     */
    private final ServiceLoader<Analyzer> service;
    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * Creates a new instance of AnalyzerService.
     *
     * @param classLoader the ClassLoader to use when dynamically loading
     *                    Analyzer and Update services
     * @param settings    the configured settings
     */
    public AnalyzerService(ClassLoader classLoader, Settings settings) {
        service = ServiceLoader.load(Analyzer.class, classLoader);
        this.settings = settings;
    }

    /**
     * Returns a list of all instances of the Analyzer interface.
     *
     * @return a list of Analyzers.
     */
    public List<Analyzer> getAnalyzers() {
        return getAnalyzers(AnalysisPhase.values());
    }

    /**
     * Returns a list of all instances of the Analyzer interface that are bound
     * to one of the given phases.
     *
     * @param phases the phases to obtain analyzers for
     * @return a list of Analyzers.
     */
    public List<Analyzer> getAnalyzers(AnalysisPhase... phases) {
        return getAnalyzers(asList(phases));
    }

    /**
     * Returns a list of all instances of the Analyzer interface that are bound
     * to one of the given phases.
     *
     * @param phases the phases to obtain analyzers for
     * @return a list of Analyzers
     */
    public List<Analyzer> getAnalyzers(List<AnalysisPhase> phases) {
        final List<Analyzer> analyzers = new ArrayList<>();
        final Iterator<Analyzer> iterator = service.iterator();
        final boolean experimentalEnabled;
        final boolean retiredEnabled;
        experimentalEnabled = settings.getBoolean(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, false);
        retiredEnabled = settings.getBoolean(Settings.KEYS.ANALYZER_RETIRED_ENABLED, false);
        while (iterator.hasNext()) {
            final Analyzer a = iterator.next();
            if (!phases.contains(a.getAnalysisPhase())) {
                continue;
            }
            if (!experimentalEnabled && a.getClass().isAnnotationPresent(Experimental.class)) {
                continue;
            }
            if (!retiredEnabled && a.getClass().isAnnotationPresent(Retired.class)) {
                continue;
            }
            LOGGER.debug("Loaded Analyzer {}", a.getName());
            analyzers.add(a);
        }
        return analyzers;
    }
}
