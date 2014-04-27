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

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * The Analyzer Service Loader. This class loads all services that implement
 * org.owasp.dependencycheck.analyzer.Analyzer.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class AnalyzerService {

    /**
     * The service loader for analyzers.
     */
    private final ServiceLoader<Analyzer> loader;

    /**
     * Creates a new instance of AnalyzerService.
     *
     * @param classLoader the ClassLoader to use when dynamically loading Analyzer and Update services
     */
    public AnalyzerService(ClassLoader classLoader) {
        loader = ServiceLoader.load(Analyzer.class, classLoader);
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
