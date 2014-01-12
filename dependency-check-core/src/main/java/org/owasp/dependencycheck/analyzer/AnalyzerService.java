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

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class AnalyzerService {

    /**
     * The analyzer service singleton.
     */
    private static AnalyzerService service;
    /**
     * The service loader for analyzers.
     */
    private final ServiceLoader<Analyzer> loader;

    /**
     * Creates a new instance of AnalyzerService.
     */
    private AnalyzerService() {
        loader = ServiceLoader.load(Analyzer.class);
    }

    /**
     * Retrieve the singleton instance of AnalyzerService.
     *
     * @return a singleton AnalyzerService.
     */
    public static synchronized AnalyzerService getInstance() {
        if (service == null) {
            service = new AnalyzerService();
        }
        return service;
    }

    /**
     * Returns an Iterator for all instances of the Analyzer interface.
     *
     * @return an iterator of Analyzers.
     */
    public Iterator<Analyzer> getAnalyzers() {
        return loader.iterator();
    }
}
