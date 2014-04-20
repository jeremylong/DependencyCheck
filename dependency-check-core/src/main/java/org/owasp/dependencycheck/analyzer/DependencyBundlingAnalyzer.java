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

import java.io.File;
import java.util.HashSet;
import java.util.Iterator;
import java.util.ListIterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.LogUtils;

/**
 * <p>
 * This analyzer ensures dependencies that should be grouped together, to remove excess noise from the report, are
 * grouped. An example would be Spring, Spring Beans, Spring MVC, etc. If they are all for the same version and have the
 * same relative path then these should be grouped into a single dependency under the core/main library.</p>
 * <p>
 * Note, this grouping only works on dependencies with identified CVE entries</p>
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DependencyBundlingAnalyzer extends AbstractAnalyzer implements Analyzer {
    /**
     * The Logger.
     */
    private static final Logger LOGGER = Logger.getLogger(DependencyBundlingAnalyzer.class.getName());
    
    //<editor-fold defaultstate="collapsed" desc="Constants and Member Variables">
    /**
     * A pattern for obtaining the first part of a filename.
     */
    private static final Pattern STARTING_TEXT_PATTERN = Pattern.compile("^[a-zA-Z]*");
    /**
     * a flag indicating if this analyzer has run. This analyzer only runs once.
     */
    private boolean analyzed = false;
    //</editor-fold>
    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Dependency Bundling Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.PRE_FINDING_ANALYSIS;

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }
    //</editor-fold>

    /**
     * Analyzes a set of dependencies. If they have been found to have the same base path and the same set of
     * identifiers they are likely related. The related dependencies are bundled into a single reportable item.
     *
     * @param ignore this analyzer ignores the dependency being analyzed
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR file.
     */
    @Override
    public void analyze(Dependency ignore, Engine engine) throws AnalysisException {
        if (!analyzed) {
            analyzed = true;
            final Set<Dependency> dependenciesToRemove = new HashSet<Dependency>();
            final ListIterator<Dependency> mainIterator = engine.getDependencies().listIterator();
            //for (Dependency nextDependency : engine.getDependencies()) {
            while (mainIterator.hasNext()) {
                final Dependency dependency = mainIterator.next();
                if (mainIterator.hasNext()) {
                    final ListIterator<Dependency> subIterator = engine.getDependencies().listIterator(mainIterator.nextIndex());
                    while (subIterator.hasNext()) {
                        final Dependency nextDependency = subIterator.next();
                        if (hashesMatch(dependency, nextDependency)) {
                            if (isCore(dependency, nextDependency)) {
                                mergeDependencies(dependency, nextDependency, dependenciesToRemove);
                            } else {
                                mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                            }
                        } else if (isShadedJar(dependency, nextDependency)) {
                            if (dependency.getFileName().toLowerCase().endsWith("pom.xml")) {
                                dependenciesToRemove.add(dependency);
                            } else {
                                dependenciesToRemove.add(nextDependency);
                            }
                        } else if (cpeIdentifiersMatch(dependency, nextDependency)
                                && hasSameBasePath(dependency, nextDependency)
                                && fileNameMatch(dependency, nextDependency)) {

                            if (isCore(dependency, nextDependency)) {
                                mergeDependencies(dependency, nextDependency, dependenciesToRemove);
                            } else {
                                mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                            }
                        }
                    }
                }
            }
            //removing dependencies here as ensuring correctness and avoiding ConcurrentUpdateExceptions
            // was difficult because of the inner iterator.
            for (Dependency d : dependenciesToRemove) {
                engine.getDependencies().remove(d);
            }
        }
    }

    /**
     * Adds the relatedDependency to the dependency's related dependencies.
     *
     * @param dependency the main dependency
     * @param relatedDependency a collection of dependencies to be removed from the main analysis loop, this is the
     * source of dependencies to remove
     * @param dependenciesToRemove a collection of dependencies that will be removed from the main analysis loop, this
     * function adds to this collection
     */
    private void mergeDependencies(final Dependency dependency, final Dependency relatedDependency, final Set<Dependency> dependenciesToRemove) {
        dependency.addRelatedDependency(relatedDependency);
        final Iterator<Dependency> i = relatedDependency.getRelatedDependencies().iterator();
        while (i.hasNext()) {
            dependency.addRelatedDependency(i.next());
            i.remove();
        }
        dependenciesToRemove.add(relatedDependency);
    }

    /**
     * Attempts to trim a maven repo to a common base path. This is typically
     * [drive]\[repo_location]\repository\[path1]\[path2].
     *
     * @param path the path to trim
     * @return a string representing the base path.
     */
    private String getBaseRepoPath(final String path) {
        int pos = path.indexOf("repository" + File.separator) + 11;
        if (pos < 0) {
            return path;
        }
        int tmp = path.indexOf(File.separator, pos);
        if (tmp <= 0) {
            return path;
        }
        if (tmp > 0) {
            pos = tmp + 1;
        }
        tmp = path.indexOf(File.separator, pos);
        if (tmp > 0) {
            pos = tmp + 1;
        }
        return path.substring(0, pos);
    }

    /**
     * Returns true if the file names (and version if it exists) of the two dependencies are sufficiently similar.
     *
     * @param dependency1 a dependency2 to compare
     * @param dependency2 a dependency2 to compare
     * @return true if the identifiers in the two supplied dependencies are equal
     */
    private boolean fileNameMatch(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency1.getFileName() == null
                || dependency2 == null || dependency2.getFileName() == null) {
            return false;
        }
        String fileName1 = dependency1.getFileName();
        String fileName2 = dependency2.getFileName();

        //update to deal with archive analyzer, the starting name maybe the same
        // as this is incorrectly looking at the starting path
        final File one = new File(fileName1);
        final File two = new File(fileName2);
        final String oneParent = one.getParent();
        final String twoParent = two.getParent();
        if (oneParent != null) {
            if (oneParent.equals(twoParent)) {
                fileName1 = one.getName();
                fileName2 = two.getName();
            } else {
                return false;
            }
        } else if (twoParent != null) {
            return false;
        }

        //version check
        final DependencyVersion version1 = DependencyVersionUtil.parseVersion(fileName1);
        final DependencyVersion version2 = DependencyVersionUtil.parseVersion(fileName2);
        if (version1 != null && version2 != null) {
            if (!version1.equals(version2)) {
                return false;
            }
        }

        //filename check
        final Matcher match1 = STARTING_TEXT_PATTERN.matcher(fileName1);
        final Matcher match2 = STARTING_TEXT_PATTERN.matcher(fileName2);
        if (match1.find() && match2.find()) {
            return match1.group().equals(match2.group());
        }

        return false;
    }

    /**
     * Returns true if the CPE identifiers in the two supplied dependencies are equal.
     *
     * @param dependency1 a dependency2 to compare
     * @param dependency2 a dependency2 to compare
     * @return true if the identifiers in the two supplied dependencies are equal
     */
    private boolean cpeIdentifiersMatch(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency1.getIdentifiers() == null
                || dependency2 == null || dependency2.getIdentifiers() == null) {
            return false;
        }
        boolean matches = false;
        int cpeCount1 = 0;
        int cpeCount2 = 0;
        for (Identifier i : dependency1.getIdentifiers()) {
            if ("cpe".equals(i.getType())) {
                cpeCount1 += 1;
            }
        }
        for (Identifier i : dependency2.getIdentifiers()) {
            if ("cpe".equals(i.getType())) {
                cpeCount2 += 1;
            }
        }
        if (cpeCount1 > 0 && cpeCount1 == cpeCount2) {
            for (Identifier i : dependency1.getIdentifiers()) {
                matches |= dependency2.getIdentifiers().contains(i);
                if (!matches) {
                    break;
                }
            }
        }
        if (LogUtils.isVerboseLoggingEnabled()) {
            final String msg = String.format("IdentifiersMatch=%s (%s, %s)", matches, dependency1.getFileName(), dependency2.getFileName());
            LOGGER.log(Level.FINE, msg);
        }
        return matches;
    }

    /**
     * Determines if the two dependencies have the same base path.
     *
     * @param dependency1 a Dependency object
     * @param dependency2 a Dependency object
     * @return true if the base paths of the dependencies are identical
     */
    private boolean hasSameBasePath(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency2 == null) {
            return false;
        }
        final File lFile = new File(dependency1.getFilePath());
        String left = lFile.getParent();
        final File rFile = new File(dependency2.getFilePath());
        String right = rFile.getParent();
        if (left == null) {
            return right == null;
        }
        if (left.equalsIgnoreCase(right)) {
            return true;
        }
        if (left.matches(".*[/\\\\]repository[/\\\\].*") && right.matches(".*[/\\\\]repository[/\\\\].*")) {
            left = getBaseRepoPath(left);
            right = getBaseRepoPath(right);
        }
        if (left.equalsIgnoreCase(right)) {
            return true;
        }
        //new code
        for (Dependency child : dependency2.getRelatedDependencies()) {
            if (hasSameBasePath(dependency1, child)) {
                return true;
            }
        }
        return false;
    }

    /**
     * This is likely a very broken attempt at determining if the 'left' dependency is the 'core' library in comparison
     * to the 'right' library.
     *
     * @param left the dependency to test
     * @param right the dependency to test against
     * @return a boolean indicating whether or not the left dependency should be considered the "core" version.
     */
    boolean isCore(Dependency left, Dependency right) {
        final String leftName = left.getFileName().toLowerCase();
        final String rightName = right.getFileName().toLowerCase();

        final boolean returnVal;
        if (!rightName.matches(".*\\.(tar|tgz|gz|zip|ear|war).+") && leftName.matches(".*\\.(tar|tgz|gz|zip|ear|war).+")
                || rightName.contains("core") && !leftName.contains("core")
                || rightName.contains("kernel") && !leftName.contains("kernel")) {
            returnVal = false;
        } else if (rightName.matches(".*\\.(tar|tgz|gz|zip|ear|war).+") && !leftName.matches(".*\\.(tar|tgz|gz|zip|ear|war).+")
                || !rightName.contains("core") && leftName.contains("core")
                || !rightName.contains("kernel") && leftName.contains("kernel")) {
            returnVal = true;
        } else {
            /*
             * considered splitting the names up and comparing the components,
             * but decided that the file name length should be sufficient as the
             * "core" component, if this follows a normal naming protocol should
             * be shorter:
             * axis2-saaj-1.4.1.jar
             * axis2-1.4.1.jar       <-----
             * axis2-kernal-1.4.1.jar
             */
            returnVal = leftName.length() <= rightName.length();
        }
        if (LogUtils.isVerboseLoggingEnabled()) {
            final String msg = String.format("IsCore=%s (%s, %s)", returnVal, left.getFileName(), right.getFileName());
            LOGGER.log(Level.FINE, msg);
        }
        return returnVal;
    }

    /**
     * Compares the SHA1 hashes of two dependencies to determine if they are equal.
     *
     * @param dependency1 a dependency object to compare
     * @param dependency2 a dependency object to compare
     * @return true if the sha1 hashes of the two dependencies match; otherwise false
     */
    private boolean hashesMatch(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency2 == null || dependency1.getSha1sum() == null || dependency2.getSha1sum() == null) {
            return false;
        }
        return dependency1.getSha1sum().equals(dependency2.getSha1sum());
    }

    /**
     * Determines if the jar is shaded and the created pom.xml identified the same CPE as the jar - if so, the pom.xml
     * dependency should be removed.
     *
     * @param dependency a dependency to check
     * @param nextDependency another dependency to check
     * @return true if on of the dependencies is a pom.xml and the identifiers between the two collections match;
     * otherwise false
     */
    private boolean isShadedJar(Dependency dependency, Dependency nextDependency) {
        final String mainName = dependency.getFileName().toLowerCase();
        final String nextName = nextDependency.getFileName().toLowerCase();
        if (mainName.endsWith(".jar") && nextName.endsWith("pom.xml")) {
            return dependency.getIdentifiers().containsAll(nextDependency.getIdentifiers());
        } else if (nextName.endsWith(".jar") && mainName.endsWith("pom.xml")) {
            return nextDependency.getIdentifiers().containsAll(dependency.getIdentifiers());
        }
        return false;
    }
}
