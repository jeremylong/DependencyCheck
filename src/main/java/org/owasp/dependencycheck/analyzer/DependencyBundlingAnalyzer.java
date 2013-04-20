/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.Iterator;
import java.util.Set;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 * <p>This analyzer ensures dependencies that should be grouped together, to
 * remove excess noise from the report, are grouped. An example would be Spring,
 * Spring Beans, Spring MVC, etc. If they are all for the same version and have
 * the same relative path then these should be grouped into a single dependency
 * under the core/main library.</p>
 * <p>Note, this grouping only works on dependencies with identified CVE
 * entries</p>
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class DependencyBundlingAnalyzer extends AbstractAnalyzer implements Analyzer {

    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final Set<String> EXTENSIONS = null;
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Dependency Bundling Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.POST_IDENTIFIER_ANALYSIS;

    /**
     * Returns a list of file EXTENSIONS supported by this analyzer.
     *
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    public Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns whether or not this analyzer can process the given extension.
     *
     * @param extension the file extension to test for support
     * @return whether or not the specified file extension is supported by this
     * analyzer.
     */
    public boolean supportsExtension(String extension) {
        return true;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }
    /**
     * The Post Analysis Action that will be set after analyzing a dependency.
     */
    private PostAnalysisAction action;

    /**
     * Analyzes a set of dependencies. If they have been found to have the same
     * base path and the same set of identifiers they are likely related. The
     * related dependencies are bundled into a single reportable item.
     *
     * @param dependency the dependency being analyzed
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        action = PostAnalysisAction.NOTHING;
        if (dependency.getIdentifiers().size() > 0) {
            for (Dependency dependencyToCheck : engine.getDependencies()) {
                if (dependency.equals(dependencyToCheck)) {
                    return;
                }
                if (identifiersMatch(dependencyToCheck, dependency)
                        && hasSameBasePath(dependencyToCheck, dependency)
                        && isCore(dependency, dependencyToCheck)) {
                    //move this dependency to be a related dependency
                    action = PostAnalysisAction.REMOVE_DEPENDENCY;
                    dependencyToCheck.addRelatedDependency(dependency);
                    //move any "related dependencies" to the new "parent" dependency
                    final Iterator<Dependency> i = dependency.getRelatedDependencies().iterator();
                    while (i.hasNext()) {
                        dependencyToCheck.addRelatedDependency(i.next());
                        i.remove();
                    }
                    return;
                }
            }
        }
    }

    /**
     * Returns true if the identifiers in the two supplied dependencies are equal.
     * @param dependency1 a dependency2 to compare
     * @param dependency2 a dependency2 to compare
     * @return true if the identifiers in the two supplied dependencies are equal
     */
    private boolean identifiersMatch(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency1.getIdentifiers() == null
                || dependency2 == null || dependency2.getIdentifiers() == null) {
            return false;
        }
        return dependency1.getIdentifiers().size() > 0
                && dependency2.getIdentifiers().equals(dependency1.getIdentifiers());
    }

    /**
     * Determines if the two dependencies have the same base path.
     * @param dependency1 a Dependency object
     * @param dependency2 a Dependency object
     * @return true if the base paths of the dependencies are identical
     */
    private boolean hasSameBasePath(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency2 == null) {
            return false;
        }
        final File lFile = new File(dependency1.getFilePath());
        final String left = lFile.getParent();
        final File rFile = new File(dependency2.getFilePath());
        final String right = rFile.getParent();
        if (left == null) {
            if (right == null) {
                return true;
            }
            return false;
        }
        return left.equalsIgnoreCase(right);
    }

    /**
     * This is likely a very broken attempt at determining if the 'left'
     * dependency is the 'core' library in comparison to the 'right' library.
     *
     * @param left the dependency to test
     * @param right the dependency to test against
     * @return a boolean indicating whether or not the left dependency should be
     * considered the "core" version.
     */
    private boolean isCore(Dependency left, Dependency right) {
        final String leftName = left.getFileName().toLowerCase();
        final String rightName = right.getFileName().toLowerCase();

        if (rightName.contains("core") && !leftName.contains("core")) {
            return false;
        } else if (!rightName.contains("core") && leftName.contains("core")) {
            return true;
        } else {
            //TODO should we be splitting the name on [-_(.\d)+] and seeing if the
            //  parts are contained in the other side?
            if (leftName.length() > rightName.length()) {
                return false;
            }
            return true;
        }
    }

    /**
     * Returns whether or not the dependency should be removed from the parent
     * list of dependencies.
     *
     * @return a PostAnalysisAction of REMOVE or NOTHING
     */
    @Override
    public PostAnalysisAction getPostAnalysisAction() {
        return action;
    }
}
