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

import java.io.FileFilter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This analyzer attempts to remove some well known false positives -
 * specifically regarding the java runtime.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class FalsePositiveAnalyzer extends AbstractAnalyzer {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(FalsePositiveAnalyzer.class);
    /**
     * The file filter used to find DLL and EXE.
     */
    private static final FileFilter DLL_EXE_FILTER = FileFilterBuilder.newInstance().addExtensions("dll", "exe").build();
    /**
     * Regex to identify core java libraries and a few other commonly
     * misidentified ones.
     */
    public static final Pattern CORE_JAVA = Pattern.compile("^cpe:/a:(sun|oracle|ibm):(j2[ems]e|"
            + "java(_platform_micro_edition|_runtime_environment|_se|virtual_machine|se_development_kit|fx)?|"
            + "jdk|jre|jsse)($|:.*)");
    /**
     * Regex to identify core jsf libraries.
     */
    public static final Pattern CORE_JAVA_JSF = Pattern.compile("^cpe:/a:(sun|oracle|ibm):jsf($|:.*)");
    /**
     * Regex to identify core java library files. This is currently incomplete.
     */
    public static final Pattern CORE_FILES = Pattern.compile("(^|/)((alt[-])?rt|jsse|jfxrt|jfr|jce|javaws|deploy|charsets)\\.jar$");
    /**
     * Regex to identify core jsf java library files. This is currently
     * incomplete.
     */
    public static final Pattern CORE_JSF_FILES = Pattern.compile("(^|/)jsf[-][^/]*\\.jar$");

    //<editor-fold defaultstate="collapsed" desc="All standard implementation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "False Positive Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.POST_IDENTIFIER_ANALYSIS;

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
        return Settings.KEYS.ANALYZER_FALSE_POSITIVE_ENABLED;
    }
    //</editor-fold>

    /**
     * Analyzes the dependencies and removes bad/incorrect CPE associations
     * based on various heuristics.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        removeJreEntries(dependency);
        removeBadMatches(dependency);
        removeBadSpringMatches(dependency);
        removeWrongVersionMatches(dependency);
        removeSpuriousCPE(dependency);
        removeDuplicativeEntriesFromJar(dependency, engine);
        addFalseNegativeCPEs(dependency);
    }

    /**
     * Removes inaccurate matches on springframework CPEs.
     *
     * @param dependency the dependency to test for and remove known inaccurate
     * CPE matches
     */
    private void removeBadSpringMatches(Dependency dependency) {
        String mustContain = null;
        for (Identifier i : dependency.getIdentifiers()) {
            if ("maven".contains(i.getType())
                    && i.getValue() != null && i.getValue().startsWith("org.springframework.")) {
                final int endPoint = i.getValue().indexOf(':', 19);
                if (endPoint >= 0) {
                    mustContain = i.getValue().substring(19, endPoint).toLowerCase();
                    break;
                }
            }
        }
        if (mustContain != null) {
            final Set<Identifier> removalSet = new HashSet<>();
            for (Identifier i : dependency.getIdentifiers()) {
                if ("cpe".contains(i.getType())
                        && i.getValue() != null
                        && i.getValue().startsWith("cpe:/a:springsource:")
                        && !i.getValue().toLowerCase().contains(mustContain)) {
                    removalSet.add(i);
                }
            }
            for (Identifier i : removalSet) {
                dependency.removeIdentifier(i);
            }
        }
    }

    /**
     * <p>
     * Intended to remove spurious CPE entries. By spurious we mean duplicate,
     * less specific CPE entries.</p>
     * <p>
     * Example:</p>
     * <code>
     * cpe:/a:some-vendor:some-product
     * cpe:/a:some-vendor:some-product:1.5
     * cpe:/a:some-vendor:some-product:1.5.2
     * </code>
     * <p>
     * Should be trimmed to:</p>
     * <code>
     * cpe:/a:some-vendor:some-product:1.5.2
     * </code>
     *
     * @param dependency the dependency being analyzed
     */
    @SuppressWarnings("null")
    private void removeSpuriousCPE(Dependency dependency) {
        final List<Identifier> ids = new ArrayList<>(dependency.getIdentifiers());
        Collections.sort(ids);
        final ListIterator<Identifier> mainItr = ids.listIterator();
        while (mainItr.hasNext()) {
            final Identifier currentId = mainItr.next();
            final VulnerableSoftware currentCpe = parseCpe(currentId.getType(), currentId.getValue());
            if (currentCpe == null) {
                continue;
            }
            final ListIterator<Identifier> subItr = ids.listIterator(mainItr.nextIndex());
            while (subItr.hasNext()) {
                final Identifier nextId = subItr.next();
                final VulnerableSoftware nextCpe = parseCpe(nextId.getType(), nextId.getValue());
                if (nextCpe == null) {
                    continue;
                }
                //TODO fix the version problem below
                if (currentCpe.getVendor().equals(nextCpe.getVendor())) {
                    if (currentCpe.getProduct().equals(nextCpe.getProduct())) {
                        // see if one is contained in the other.. remove the contained one from dependency.getIdentifier
                        final String currentVersion = currentCpe.getVersion();
                        final String nextVersion = nextCpe.getVersion();
                        if (currentVersion == null && nextVersion == null) {
                            //how did we get here?
                            LOGGER.debug("currentVersion and nextVersion are both null?");
                        } else if (currentVersion == null && nextVersion != null) {
                            dependency.removeIdentifier(currentId);
                        } else if (nextVersion == null && currentVersion != null) {
                            dependency.removeIdentifier(nextId);
                        } else if (currentVersion.length() < nextVersion.length()) {
                            if (nextVersion.startsWith(currentVersion) || "-".equals(currentVersion)) {
                                dependency.removeIdentifier(currentId);
                            }
                        } else if (currentVersion.startsWith(nextVersion) || "-".equals(nextVersion)) {
                            dependency.removeIdentifier(nextId);
                        }
                    }
                }
            }
        }
    }

    /**
     * Removes any CPE entries for the JDK/JRE unless the filename ends with
     * rt.jar
     *
     * @param dependency the dependency to remove JRE CPEs from
     */
    private void removeJreEntries(Dependency dependency) {
        final Set<Identifier> removalSet = new HashSet<>();
        for (Identifier i : dependency.getIdentifiers()) {
            final Matcher coreCPE = CORE_JAVA.matcher(i.getValue());
            final Matcher coreFiles = CORE_FILES.matcher(dependency.getFileName());
            if (coreCPE.matches() && !coreFiles.matches()) {
                removalSet.add(i);
            }
            final Matcher coreJsfCPE = CORE_JAVA_JSF.matcher(i.getValue());
            final Matcher coreJsfFiles = CORE_JSF_FILES.matcher(dependency.getFileName());
            if (coreJsfCPE.matches() && !coreJsfFiles.matches()) {
                removalSet.add(i);
            }
        }
        for (Identifier i : removalSet) {
            dependency.removeIdentifier(i);
        }
    }

    /**
     * Parses a CPE string into an IndexEntry.
     *
     * @param type the type of identifier
     * @param value the cpe identifier to parse
     * @return an VulnerableSoftware object constructed from the identifier
     */
    private VulnerableSoftware parseCpe(String type, String value) {
        if (!"cpe".equals(type)) {
            return null;
        }
        final VulnerableSoftware cpe = new VulnerableSoftware();
        try {
            cpe.parseName(value);
        } catch (UnsupportedEncodingException ex) {
            LOGGER.trace("", ex);
            return null;
        }
        return cpe;
    }

    /**
     * Removes bad CPE matches for a dependency. Unfortunately, right now these
     * are hard-coded patches for specific problems identified when testing this
     * on a LARGE volume of jar files.
     *
     * @param dependency the dependency to analyze
     */
    protected void removeBadMatches(Dependency dependency) {

        /* TODO - can we utilize the pom's groupid and artifactId to filter??? most of
         * these are due to low quality data.  Other idea would be to say any CPE
         * found based on LOW confidence evidence should have a different CPE type? (this
         * might be a better solution then just removing the URL for "best-guess" matches).
         */
        //Set<Evidence> groupId = dependency.getVendorEvidence().getEvidence("pom", "groupid");
        //Set<Evidence> artifactId = dependency.getVendorEvidence().getEvidence("pom", "artifactid");
        for (Identifier i : dependency.getIdentifiers()) {
            //TODO move this startsWith expression to the base suppression file
            if ("cpe".equals(i.getType())) {
                if ((i.getValue().matches(".*c\\+\\+.*")
                        || i.getValue().startsWith("cpe:/a:file:file")
                        || i.getValue().startsWith("cpe:/a:mozilla:mozilla")
                        || i.getValue().startsWith("cpe:/a:cvs:cvs")
                        || i.getValue().startsWith("cpe:/a:ftp:ftp")
                        || i.getValue().startsWith("cpe:/a:tcp:tcp")
                        || i.getValue().startsWith("cpe:/a:ssh:ssh")
                        || i.getValue().startsWith("cpe:/a:lookup:lookup"))
                        && (dependency.getFileName().toLowerCase().endsWith(".jar")
                        || dependency.getFileName().toLowerCase().endsWith("pom.xml")
                        || dependency.getFileName().toLowerCase().endsWith(".dll")
                        || dependency.getFileName().toLowerCase().endsWith(".exe")
                        || dependency.getFileName().toLowerCase().endsWith(".nuspec")
                        || dependency.getFileName().toLowerCase().endsWith(".zip")
                        || dependency.getFileName().toLowerCase().endsWith(".sar")
                        || dependency.getFileName().toLowerCase().endsWith(".apk")
                        || dependency.getFileName().toLowerCase().endsWith(".tar")
                        || dependency.getFileName().toLowerCase().endsWith(".gz")
                        || dependency.getFileName().toLowerCase().endsWith(".tgz")
                        || dependency.getFileName().toLowerCase().endsWith(".ear")
                        || dependency.getFileName().toLowerCase().endsWith(".war"))) {
                    //itr.remove();
                    dependency.removeIdentifier(i);
                } else if ((i.getValue().startsWith("cpe:/a:jquery:jquery")
                        || i.getValue().startsWith("cpe:/a:prototypejs:prototype")
                        || i.getValue().startsWith("cpe:/a:yahoo:yui"))
                        && (dependency.getFileName().toLowerCase().endsWith(".jar")
                        || dependency.getFileName().toLowerCase().endsWith("pom.xml")
                        || dependency.getFileName().toLowerCase().endsWith(".dll")
                        || dependency.getFileName().toLowerCase().endsWith(".exe"))) {
                    //itr.remove();
                    dependency.removeIdentifier(i);
                } else if ((i.getValue().startsWith("cpe:/a:microsoft:excel")
                        || i.getValue().startsWith("cpe:/a:microsoft:word")
                        || i.getValue().startsWith("cpe:/a:microsoft:visio")
                        || i.getValue().startsWith("cpe:/a:microsoft:powerpoint")
                        || i.getValue().startsWith("cpe:/a:microsoft:office")
                        || i.getValue().startsWith("cpe:/a:core_ftp:core_ftp"))
                        && (dependency.getFileName().toLowerCase().endsWith(".jar")
                        || dependency.getFileName().toLowerCase().endsWith(".ear")
                        || dependency.getFileName().toLowerCase().endsWith(".war")
                        || dependency.getFileName().toLowerCase().endsWith("pom.xml"))) {
                    //itr.remove();
                    dependency.removeIdentifier(i);
                } else if (i.getValue().startsWith("cpe:/a:apache:maven")
                        && !dependency.getFileName().toLowerCase().matches("maven-core-[\\d\\.]+\\.jar")) {
                    //itr.remove();
                    dependency.removeIdentifier(i);
                } else if (i.getValue().startsWith("cpe:/a:m-core:m-core")) {
                    boolean found = false;
                    for (Evidence e : dependency.getEvidence(EvidenceType.PRODUCT)) {
                        if ("m-core".equalsIgnoreCase(e.getValue())) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        for (Evidence e : dependency.getEvidence(EvidenceType.VENDOR)) {
                            if ("m-core".equalsIgnoreCase(e.getValue())) {
                                found = true;
                                break;
                            }
                        }
                    }
                    if (!found) {
                        //itr.remove();
                        dependency.removeIdentifier(i);
                    }
                } else if (i.getValue().startsWith("cpe:/a:jboss:jboss")
                        && !dependency.getFileName().toLowerCase().matches("jboss-?[\\d\\.-]+(GA)?\\.jar")) {
                    //itr.remove();
                    dependency.removeIdentifier(i);
                }
            }
        }
    }

    /**
     * Removes CPE matches for the wrong version of a dependency. Currently,
     * this only covers Axis 1 & 2.
     *
     * @param dependency the dependency to analyze
     */
    private void removeWrongVersionMatches(Dependency dependency) {
        final Set<Identifier> identifiersToRemove = new HashSet<>();
        final String fileName = dependency.getFileName();
        if (fileName != null && fileName.contains("axis2")) {
            for (Identifier i : dependency.getIdentifiers()) {
                if ("cpe".equals(i.getType())) {
                    final String cpe = i.getValue();
                    if (cpe != null && (cpe.startsWith("cpe:/a:apache:axis:") || "cpe:/a:apache:axis".equals(cpe))) {
                        identifiersToRemove.add(i);
                    }
                }
            }
        } else if (fileName != null && fileName.contains("axis")) {
            for (Identifier i : dependency.getIdentifiers()) {
                if ("cpe".equals(i.getType())) {
                    final String cpe = i.getValue();
                    if (cpe != null && (cpe.startsWith("cpe:/a:apache:axis2:") || "cpe:/a:apache:axis2".equals(cpe))) {
                        identifiersToRemove.add(i);
                    }
                }
            }
        }
        for (Identifier i : identifiersToRemove) {
            dependency.removeIdentifier(i);
        }
    }

    /**
     * There are some known CPE entries, specifically regarding sun and oracle
     * products due to the acquisition and changes in product names, that based
     * on given evidence we can add the related CPE entries to ensure a complete
     * list of CVE entries.
     *
     * @param dependency the dependency being analyzed
     */
    private void addFalseNegativeCPEs(Dependency dependency) {
        //TODO move this to the hint analyzer
        for (final Identifier identifier : dependency.getIdentifiers()) {
            if ("cpe".equals(identifier.getType()) && identifier.getValue() != null
                    && (identifier.getValue().startsWith("cpe:/a:oracle:opensso:")
                    || identifier.getValue().startsWith("cpe:/a:oracle:opensso_enterprise:")
                    || identifier.getValue().startsWith("cpe:/a:sun:opensso_enterprise:")
                    || identifier.getValue().startsWith("cpe:/a:sun:opensso:"))) {
                final String[] parts = identifier.getValue().split(":");
                final int pos = parts[0].length() + parts[1].length() + parts[2].length() + parts[3].length() + 4;
                final String newCpe = String.format("cpe:/a:sun:opensso_enterprise:%s", identifier.getValue().substring(pos));
                final String newCpe2 = String.format("cpe:/a:oracle:opensso_enterprise:%s", identifier.getValue().substring(pos));
                final String newCpe3 = String.format("cpe:/a:sun:opensso:%s", identifier.getValue().substring(pos));
                final String newCpe4 = String.format("cpe:/a:oracle:opensso:%s", identifier.getValue().substring(pos));
                try {
                    dependency.addIdentifier("cpe", newCpe,
                            String.format(CPEAnalyzer.NVD_SEARCH_URL, URLEncoder.encode(newCpe, StandardCharsets.UTF_8.name())),
                            identifier.getConfidence());
                    dependency.addIdentifier("cpe", newCpe2,
                            String.format(CPEAnalyzer.NVD_SEARCH_URL, URLEncoder.encode(newCpe2, StandardCharsets.UTF_8.name())),
                            identifier.getConfidence());
                    dependency.addIdentifier("cpe", newCpe3,
                            String.format(CPEAnalyzer.NVD_SEARCH_URL, URLEncoder.encode(newCpe3, StandardCharsets.UTF_8.name())),
                            identifier.getConfidence());
                    dependency.addIdentifier("cpe", newCpe4,
                            String.format(CPEAnalyzer.NVD_SEARCH_URL, URLEncoder.encode(newCpe4, StandardCharsets.UTF_8.name())),
                            identifier.getConfidence());
                } catch (UnsupportedEncodingException ex) {
                    LOGGER.debug("", ex);
                }
            }
            if ("cpe".equals(identifier.getType()) && identifier.getValue() != null
                    && identifier.getValue().startsWith("cpe:/a:apache:santuario_xml_security_for_java:")) {
                final String[] parts = identifier.getValue().split(":");
                final int pos = parts[0].length() + parts[1].length() + parts[2].length() + parts[3].length() + 4;
                final String newCpe = String.format("cpe:/a:apache:xml_security_for_java:%s", identifier.getValue().substring(pos));
                try {
                    dependency.addIdentifier("cpe", newCpe,
                            String.format(CPEAnalyzer.NVD_SEARCH_URL, URLEncoder.encode(newCpe, StandardCharsets.UTF_8.name())),
                            identifier.getConfidence());
                } catch (UnsupportedEncodingException ex) {
                    LOGGER.debug("", ex);
                }
            }
        }
    }

    /**
     * Removes duplicate entries identified that are contained within JAR files.
     * These occasionally crop up due to POM entries or other types of files
     * (such as DLLs and EXEs) being contained within the JAR.
     *
     * @param dependency the dependency that might be a duplicate
     * @param engine the engine used to scan all dependencies
     */
    private synchronized void removeDuplicativeEntriesFromJar(Dependency dependency, Engine engine) {
        if (dependency.getFileName().toLowerCase().endsWith("pom.xml")
                || DLL_EXE_FILTER.accept(dependency.getActualFile())) {
            String parentPath = dependency.getFilePath().toLowerCase();
            if (parentPath.contains(".jar")) {
                parentPath = parentPath.substring(0, parentPath.indexOf(".jar") + 4);
                final Dependency[] dependencies = engine.getDependencies();
                final Dependency parent = findDependency(parentPath, dependencies);
                if (parent != null) {
                    boolean remove = false;
                    for (Identifier i : dependency.getIdentifiers()) {
                        if ("cpe".equals(i.getType())) {
                            final String trimmedCPE = trimCpeToVendor(i.getValue());
                            for (Identifier parentId : parent.getIdentifiers()) {
                                if ("cpe".equals(parentId.getType()) && parentId.getValue().startsWith(trimmedCPE)) {
                                    remove |= true;
                                }
                            }
                        }
                        if (!remove) { //we can escape early
                            return;
                        }
                    }
                    if (remove) {
                        engine.removeDependency(dependency);
                    }
                }
            }
        }
    }

    /**
     * Retrieves a given dependency, based on a given path, from a list of
     * dependencies.
     *
     * @param dependencyPath the path of the dependency to return
     * @param dependencies the array of dependencies to search
     * @return the dependency object for the given path, otherwise null
     */
    private Dependency findDependency(String dependencyPath, Dependency[] dependencies) {
        for (Dependency d : dependencies) {
            if (d.getFilePath().equalsIgnoreCase(dependencyPath)) {
                return d;
            }
        }
        return null;
    }

    /**
     * Takes a full CPE and returns the CPE trimmed to include only vendor and
     * product.
     *
     * @param value the CPE value to trim
     * @return a CPE value that only includes the vendor and product
     */
    private String trimCpeToVendor(String value) {
        //cpe:/a:jruby:jruby:1.0.8
        final int pos1 = value.indexOf(':', 7); //right of vendor
        final int pos2 = value.indexOf(':', pos1 + 1); //right of product
        if (pos2 < 0) {
            return value;
        } else {
            return value.substring(0, pos2);
        }
    }
}
