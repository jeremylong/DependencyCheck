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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 * <p>
 * This analyzer ensures dependencies that should be grouped together, to remove
 * excess noise from the report, are grouped. An example would be Spring, Spring
 * Beans, Spring MVC, etc. If they are all for the same version and have the
 * same relative path then these should be grouped into a single dependency
 * under the core/main library.</p>
 * <p>
 * Note, this grouping only works on dependencies with identified CVE
 * entries</p>
 *
 * @author Jeremy Long
 */
@ThreadSafe
public abstract class AbstractDependencyComparingAnalyzer extends AbstractAnalyzer {

    /**
     * a flag indicating if this analyzer has run. This analyzer only runs once.
     */
    private boolean analyzed = false;

    /**
     * Returns a flag indicating if this analyzer has run. This analyzer only
     * runs once. Note this is currently only used in the unit tests.
     *
     * @return a flag indicating if this analyzer has run. This analyzer only
     * runs once
     */
    protected synchronized boolean getAnalyzed() {
        return analyzed;
    }

    /**
     * Does not support parallel processing as it only runs once and then
     * operates on <em>all</em> dependencies.
     *
     * @return whether or not parallel processing is enabled
     * @see #analyze(Dependency, Engine)
     */
    @Override
    public final boolean supportsParallelProcessing() {
        return false;
    }

    /**
     * Analyzes a set of dependencies. If they have been found to have the same
     * base path and the same set of identifiers they are likely related. The
     * related dependencies are bundled into a single reportable item.
     *
     * @param ignore this analyzer ignores the dependency being analyzed
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    @Override
    protected synchronized void analyzeDependency(Dependency ignore, Engine engine) throws AnalysisException {
        if (!analyzed) {
            analyzed = true;
            final Set<Dependency> dependenciesToRemove = new HashSet<>();

            final Dependency[] dependencies = engine.getDependencies();
            if (dependencies.length < 2) {
                return;
            }
            Arrays.sort(dependencies, Dependency.NAME_COMPARATOR);
            for (int x = 0; x < dependencies.length - 1; x++) {
                final Dependency dependency = dependencies[x];
                if (!dependenciesToRemove.contains(dependency)) {
                    for (int y = x + 1; y < dependencies.length; y++) {
                        final Dependency nextDependency = dependencies[y];
                        if (evaluateDependencies(dependency, nextDependency, dependenciesToRemove)) {
                            break;
                        }
                    }
                }
            }
            dependenciesToRemove.forEach((d) -> engine.removeDependency(d));
        }
    }

    /**
     * Evaluates the dependencies
     *
     * @param dependency a dependency to compare
     * @param nextDependency a dependency to compare
     * @param dependenciesToRemove a set of dependencies that will be removed
     * @return true if a dependency is removed; otherwise false
     */
    protected abstract boolean evaluateDependencies(Dependency dependency,
            Dependency nextDependency, Set<Dependency> dependenciesToRemove);
}
