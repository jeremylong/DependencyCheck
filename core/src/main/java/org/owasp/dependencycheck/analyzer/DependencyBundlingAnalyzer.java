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

import com.vdurmont.semver4j.Semver;
import com.vdurmont.semver4j.Semver.SemverType;
import com.vdurmont.semver4j.SemverException;
import java.io.File;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
public class DependencyBundlingAnalyzer extends AbstractDependencyComparingAnalyzer {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DependencyBundlingAnalyzer.class);

    /**
     * A pattern for obtaining the first part of a filename.
     */
    private static final Pattern STARTING_TEXT_PATTERN = Pattern.compile("^[a-zA-Z0-9]*");

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Dependency Bundling Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.FINAL;

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_DEPENDENCY_BUNDLING_ENABLED;
    }

    /**
     * Evaluates the dependencies
     *
     * @param dependency a dependency to compare
     * @param nextDependency a dependency to compare
     * @param dependenciesToRemove a set of dependencies that will be removed
     * @return true if a dependency is removed; otherwise false
     */
    @Override
    protected boolean evaluateDependencies(final Dependency dependency, final Dependency nextDependency, final Set<Dependency> dependenciesToRemove) {
        if (hashesMatch(dependency, nextDependency)) {
            if (!containedInWar(dependency.getFilePath())
                    && !containedInWar(nextDependency.getFilePath())) {
                if (firstPathIsShortest(dependency.getFilePath(), nextDependency.getFilePath())) {
                    mergeDependencies(dependency, nextDependency, dependenciesToRemove);
                } else {
                    mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                    return true; //since we merged into the next dependency - skip forward to the next in mainIterator
                }
            }
        } else if (isShadedJar(dependency, nextDependency)) {
            if (dependency.getFileName().toLowerCase().endsWith("pom.xml")) {
                mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                nextDependency.removeRelatedDependencies(dependency);
                return true;
            } else {
                mergeDependencies(dependency, nextDependency, dependenciesToRemove);
                dependency.removeRelatedDependencies(nextDependency);
            }
        } else if (cpeIdentifiersMatch(dependency, nextDependency)
                && hasSameBasePath(dependency, nextDependency)
                && vulnCountMatches(dependency, nextDependency)
                && fileNameMatch(dependency, nextDependency)) {
            if (isCore(dependency, nextDependency)) {
                mergeDependencies(dependency, nextDependency, dependenciesToRemove);
            } else {
                mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                return true; //since we merged into the next dependency - skip forward to the next in mainIterator
            }
        } else if (ecoSystemIs(AbstractNpmAnalyzer.NPM_DEPENDENCY_ECOSYSTEM, dependency, nextDependency)
                && namesAreEqual(dependency, nextDependency)
                && npmVersionsMatch(dependency.getVersion(), nextDependency.getVersion())) {

            if (!dependency.isVirtual()) {
                DependencyMergingAnalyzer.mergeDependencies(dependency, nextDependency, dependenciesToRemove);
            } else {
                DependencyMergingAnalyzer.mergeDependencies(nextDependency, dependency, dependenciesToRemove);
                return true;
            }
        }
        return false;
    }

    /**
     * Adds the relatedDependency to the dependency's related dependencies.
     *
     * @param dependency the main dependency
     * @param relatedDependency a collection of dependencies to be removed from
     * the main analysis loop, this is the source of dependencies to remove
     * @param dependenciesToRemove a collection of dependencies that will be
     * removed from the main analysis loop, this function adds to this
     * collection
     */
    public static void mergeDependencies(final Dependency dependency,
            final Dependency relatedDependency, final Set<Dependency> dependenciesToRemove) {
        dependency.addRelatedDependency(relatedDependency);
        for (Dependency d : relatedDependency.getRelatedDependencies()) {
            dependency.addRelatedDependency(d);
            relatedDependency.removeRelatedDependencies(d);
        }
        if (dependency.getSha1sum().equals(relatedDependency.getSha1sum())) {
            dependency.addAllProjectReferences(relatedDependency.getProjectReferences());
        }
        if (dependenciesToRemove != null) {
            dependenciesToRemove.add(relatedDependency);
        }
    }

    /**
     * Attempts to trim a maven repo to a common base path. This is typically
     * [drive]\[repo_location]\repository\[path1]\[path2].
     *
     * @param path the path to trim
     * @return a string representing the base path.
     */
    private String getBaseRepoPath(final String path) {
        int pos;
        if (path.contains("local-repo")) {
            pos = path.indexOf("local-repo" + File.separator) + 11;
        } else {
            pos = path.indexOf("repository" + File.separator) + 11;
        }
        if (pos < 0) {
            return path;
        }
        int tmp = path.indexOf(File.separator, pos);
        if (tmp <= 0) {
            return path;
        }
        //below is always true
        //if (tmp > 0) {
        pos = tmp + 1;
        //}
        tmp = path.indexOf(File.separator, pos);
        if (tmp > 0) {
            pos = tmp + 1;
        }
        return path.substring(0, pos);
    }

    /**
     * Returns true if the file names (and version if it exists) of the two
     * dependencies are sufficiently similar.
     *
     * @param dependency1 a dependency2 to compare
     * @param dependency2 a dependency2 to compare
     * @return true if the identifiers in the two supplied dependencies are
     * equal
     */
    private boolean fileNameMatch(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency1.getFileName() == null
                || dependency2 == null || dependency2.getFileName() == null) {
            return false;
        }
        final String fileName1 = dependency1.getActualFile().getName();
        final String fileName2 = dependency2.getActualFile().getName();

        //version check
        final DependencyVersion version1 = DependencyVersionUtil.parseVersion(fileName1);
        final DependencyVersion version2 = DependencyVersionUtil.parseVersion(fileName2);
        if (version1 != null && version2 != null && !version1.equals(version2)) {
            return false;
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
     * Returns true if the CPE identifiers in the two supplied dependencies are
     * equal.
     *
     * @param dependency1 a dependency2 to compare
     * @param dependency2 a dependency2 to compare
     * @return true if the identifiers in the two supplied dependencies are
     * equal
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
                if ("cpe".equals(i.getType())) {
                    matches |= dependency2.getIdentifiers().contains(i);
                    if (!matches) {
                        break;
                    }
                }
            }
        }
        LOGGER.debug("IdentifiersMatch={} ({}, {})", matches, dependency1.getFileName(), dependency2.getFileName());
        return matches;
    }

    /**
     * Returns true if the two dependencies have the same vulnerability count.
     *
     * @param dependency1 a dependency2 to compare
     * @param dependency2 a dependency2 to compare
     * @return true if the two dependencies have the same vulnerability count
     */
    private boolean vulnCountMatches(Dependency dependency1, Dependency dependency2) {
        return dependency1.getVulnerabilities() != null && dependency2.getVulnerabilities() != null
                && dependency1.getVulnerabilities().size() == dependency2.getVulnerabilities().size();

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
        } else if (right == null) {
            return false;
        }
        if (left.equalsIgnoreCase(right)) {
            return true;
        }

        if (left.matches(".*[/\\\\](repository|local-repo)[/\\\\].*") && right.matches(".*[/\\\\](repository|local-repo)[/\\\\].*")) {
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
     * This is likely a very broken attempt at determining if the 'left'
     * dependency is the 'core' library in comparison to the 'right' library.
     *
     * @param left the dependency to test
     * @param right the dependency to test against
     * @return a boolean indicating whether or not the left dependency should be
     * considered the "core" version.
     */
    protected boolean isCore(Dependency left, Dependency right) {
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
             * axis2-kernel-1.4.1.jar
             */
            returnVal = leftName.length() <= rightName.length();
        }
        LOGGER.debug("IsCore={} ({}, {})", returnVal, left.getFileName(), right.getFileName());
        return returnVal;
    }

    /**
     * Compares the SHA1 hashes of two dependencies to determine if they are
     * equal.
     *
     * @param dependency1 a dependency object to compare
     * @param dependency2 a dependency object to compare
     * @return true if the sha1 hashes of the two dependencies match; otherwise
     * false
     */
    private boolean hashesMatch(Dependency dependency1, Dependency dependency2) {
        if (dependency1 == null || dependency2 == null || dependency1.getSha1sum() == null || dependency2.getSha1sum() == null) {
            return false;
        }
        return dependency1.getSha1sum().equals(dependency2.getSha1sum());
    }

    /**
     * Determines if the jar is shaded and the created pom.xml identified the
     * same CPE as the jar - if so, the pom.xml dependency should be removed.
     *
     * @param dependency a dependency to check
     * @param nextDependency another dependency to check
     * @return true if on of the dependencies is a pom.xml and the identifiers
     * between the two collections match; otherwise false
     */
    private boolean isShadedJar(Dependency dependency, Dependency nextDependency) {
        if (dependency == null || dependency.getFileName() == null
                || nextDependency == null || nextDependency.getFileName() == null) {
            return false;
        }
        final String mainName = dependency.getFileName().toLowerCase();
        final String nextName = nextDependency.getFileName().toLowerCase();
        if (mainName.endsWith(".jar") && nextName.endsWith("pom.xml")) {
            return dependency.getIdentifiers().containsAll(nextDependency.getIdentifiers());
        } else if (nextName.endsWith(".jar") && mainName.endsWith("pom.xml")) {
            return nextDependency.getIdentifiers().containsAll(dependency.getIdentifiers());
        }
        return false;
    }

    /**
     * Determines which path is shortest; if path lengths are equal then we use
     * compareTo of the string method to determine if the first path is smaller.
     *
     * @param left the first path to compare
     * @param right the second path to compare
     * @return <code>true</code> if the leftPath is the shortest; otherwise
     * <code>false</code>
     */
    protected boolean firstPathIsShortest(String left, String right) {
        if (left.contains("dctemp")) {
            return false;
        }
        final String leftPath = left.replace('\\', '/');
        final String rightPath = right.replace('\\', '/');

        final int leftCount = countChar(leftPath, '/');
        final int rightCount = countChar(rightPath, '/');
        if (leftCount == rightCount) {
            return leftPath.compareTo(rightPath) <= 0;
        } else {
            return leftCount < rightCount;
        }
    }

    /**
     * Counts the number of times the character is present in the string.
     *
     * @param string the string to count the characters in
     * @param c the character to count
     * @return the number of times the character is present in the string
     */
    private int countChar(String string, char c) {
        int count = 0;
        final int max = string.length();
        for (int i = 0; i < max; i++) {
            if (c == string.charAt(i)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Checks if the given file path is contained within a war or ear file.
     *
     * @param filePath the file path to check
     * @return true if the path contains '.war\' or '.ear\'.
     */
    private boolean containedInWar(String filePath) {
        return filePath != null && filePath.matches(".*\\.(ear|war)[\\\\/].*");
    }

    /**
     * Determine if the dependency ecosystem is equal in the given dependencies.
     *
     * @param ecoSystem the ecosystem to validate against
     * @param dependency a dependency to compare
     * @param nextDependency a dependency to compare
     * @return true if the ecosystem is equal in both dependencies; otherwise
     * false
     */
    private boolean ecoSystemIs(String ecoSystem, Dependency dependency, Dependency nextDependency) {
        return ecoSystem.equals(dependency.getEcosystem()) && ecoSystem.equals(nextDependency.getEcosystem());
    }

    /**
     * Determine if the dependency name is equal in the given dependencies.
     *
     * @param dependency a dependency to compare
     * @param nextDependency a dependency to compare
     * @return true if the name is equal in both dependencies; otherwise false
     */
    private boolean namesAreEqual(Dependency dependency, Dependency nextDependency) {
        return dependency.getName() != null && dependency.getName().equals(nextDependency.getName());
    }

    /**
     * Determine if the dependency version is equal in the given dependencies.
     * This method attempts to evaluate version range checks.
     *
     * @param current a dependency version to compare
     * @param next a dependency version to compare
     * @return true if the version is equal in both dependencies; otherwise
     * false
     */
    public static boolean npmVersionsMatch(String current, String next) {
        String left = current;
        String right = next;
        if (left == null || right == null) {
            return false;
        }
        if (left.equals(right) || "*".equals(left) || "*".equals(right)) {
            return true;
        }
        if (left.contains(" ")) { // we have a version string from package.json
            if (right.contains(" ")) { // we can't evaluate this ">=1.5.4 <2.0.0" vs "2 || 3"
                return false;
            }
            if (!right.matches("^\\d.*$")) {
                right = stripLeadingNonNumeric(right);
                if (right == null) {
                    return false;
                }
            }
            try {
                final Semver v = new Semver(right, SemverType.NPM);
                return v.satisfies(left);
            } catch (SemverException ex) {
                LOGGER.trace("ignore", ex);
            }
        } else {
            if (!left.matches("^\\d.*$")) {
                left = stripLeadingNonNumeric(left);
                if (left == null || left.isEmpty()) {
                    return false;
                }
            }
            try {
                Semver v = new Semver(left, SemverType.NPM);
                if (!right.isEmpty() && v.satisfies(right)) {
                    return true;
                }
                if (!right.contains(" ")) {
                    left = current;
                    right = stripLeadingNonNumeric(right);
                    if (right != null) {
                        v = new Semver(right, SemverType.NPM);
                        return v.satisfies(left);
                    }
                }
            } catch (SemverException ex) {
                LOGGER.trace("ignore", ex);
            } catch (NullPointerException ex) {
                LOGGER.error("SemVer comparison error: left:\"{}\", right:\"{}\"", left, right);
                LOGGER.debug("SemVer comparison resulted in NPE", ex);
            }
        }
        return false;
    }

    /**
     * Strips leading non-numeric values from the start of the string. If no
     * numbers are present this will return null.
     *
     * @param str the string to modify
     * @return the string without leading non-numeric characters
     */
    private static String stripLeadingNonNumeric(String str) {
        for (int x = 0; x < str.length(); x++) {
            if (Character.isDigit(str.codePointAt(x))) {
                return str.substring(x);
            }
        }
        return null;
    }

}
