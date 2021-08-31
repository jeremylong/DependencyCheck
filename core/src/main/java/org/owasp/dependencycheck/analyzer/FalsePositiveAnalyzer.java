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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.FileFilter;
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
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.utils.FileFilterBuilder;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.Part;

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
        for (Identifier i : dependency.getSoftwareIdentifiers()) {
            if (i.getValue() != null && i.getValue().startsWith("org.springframework.")) {
                final int endPoint = i.getValue().indexOf(':', 19);
                if (endPoint >= 0) {
                    mustContain = i.getValue().substring(19, endPoint).toLowerCase();
                    break;
                }
            }
        }
        if (mustContain != null) {
            final Set<Identifier> removalSet = new HashSet<>();
            for (Identifier i : dependency.getVulnerableSoftwareIdentifiers()) {
                if (i.getValue() != null
                        && i.getValue().startsWith("cpe:/a:springsource:")
                        && !i.getValue().toLowerCase().contains(mustContain)) {
                    removalSet.add(i);
                }
            }
            removalSet.forEach(dependency::removeVulnerableSoftwareIdentifier);
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
    //CSOFF: NestedIfDepth
    @SuppressWarnings("null")
    @SuppressFBWarnings(justification = "null checks are working correctly to prevent NPE", value = {"NP_NULL_ON_SOME_PATH_MIGHT_BE_INFEASIBLE"})
    private void removeSpuriousCPE(Dependency dependency) {
        final List<Identifier> ids = new ArrayList<>(dependency.getVulnerableSoftwareIdentifiers());
        Collections.sort(ids);
        final ListIterator<Identifier> mainItr = ids.listIterator();
        while (mainItr.hasNext()) {
            final Identifier temp = mainItr.next();
            if (temp instanceof CpeIdentifier) {
                final CpeIdentifier currentId = (CpeIdentifier) temp;
                final Cpe currentCpe = currentId.getCpe();
                final ListIterator<Identifier> subItr = ids.listIterator(mainItr.nextIndex());
                while (subItr.hasNext()) {
                    final Identifier nextId = subItr.next();
                    if (nextId instanceof CpeIdentifier) {
                        final CpeIdentifier nextCpeId = (CpeIdentifier) nextId;
                        final Cpe nextCpe = nextCpeId.getCpe();
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
                                    dependency.removeVulnerableSoftwareIdentifier(currentId);
                                } else if (nextVersion == null && currentVersion != null) {
                                    dependency.removeVulnerableSoftwareIdentifier(nextId);
                                } else if (currentVersion.length() < nextVersion.length()) {
                                    if (nextVersion.startsWith(currentVersion) || "-".equals(currentVersion)) {
                                        dependency.removeVulnerableSoftwareIdentifier(currentId);
                                    }
                                } else if (currentVersion.startsWith(nextVersion) || "-".equals(nextVersion)) {
                                    dependency.removeVulnerableSoftwareIdentifier(nextId);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    //CSON: NestedIfDepth

    /**
     * Removes any CPE entries for the JDK/JRE unless the filename ends with
     * rt.jar
     *
     * @param dependency the dependency to remove JRE CPEs from
     */
    private void removeJreEntries(Dependency dependency) {
        final Set<Identifier> removalSet = new HashSet<>();
        dependency.getVulnerableSoftwareIdentifiers().forEach(i -> {
            final Matcher coreCPE = CORE_JAVA.matcher(i.getValue());
            final Matcher coreFiles = CORE_FILES.matcher(dependency.getFileName());
            final Matcher coreJsfCPE = CORE_JAVA_JSF.matcher(i.getValue());
            final Matcher coreJsfFiles = CORE_JSF_FILES.matcher(dependency.getFileName());
            if ((coreCPE.matches() && !coreFiles.matches())
                    || (coreJsfCPE.matches() && !coreJsfFiles.matches())) {
                removalSet.add(i);
            }

        });
        removalSet.forEach((i) -> dependency.removeVulnerableSoftwareIdentifier(i));
    }

    /**
     * Removes bad CPE matches for a dependency. Unfortunately, right now these
     * are hard-coded patches for specific problems identified when testing this
     * on a LARGE volume of jar files.
     *
     * @param dependency the dependency to analyze
     */
    protected void removeBadMatches(Dependency dependency) {

        final Set<Identifier> toRemove = new HashSet<>();
        /* TODO - can we utilize the pom's groupid and artifactId to filter??? most of
         * these are due to low quality data.  Other idea would be to say any CPE
         * found based on LOW confidence evidence should have a different CPE type? (this
         * might be a better solution then just removing the URL for "best-guess" matches).
         */
        //Set<Evidence> groupId = dependency.getVendorEvidence().getEvidence("pom", "groupid");
        //Set<Evidence> artifactId = dependency.getVendorEvidence().getEvidence("pom", "artifactid");
        for (Identifier i : dependency.getVulnerableSoftwareIdentifiers()) {
            //TODO move this startsWith expression to the base suppression file
            if (i instanceof CpeIdentifier) {
                final CpeIdentifier cpeId = (CpeIdentifier) i;
                final Cpe cpe = cpeId.getCpe();
                if ((cpe.getProduct().matches(".*c\\+\\+.*")
                        || ("file".equals(cpe.getVendor()) && "file".equals(cpe.getProduct()))
                        || ("mozilla".equals(cpe.getVendor()) && "mozilla".equals(cpe.getProduct()))
                        || ("cvs".equals(cpe.getVendor()) && "cvs".equals(cpe.getProduct()))
                        || ("ftp".equals(cpe.getVendor()) && "ftp".equals(cpe.getProduct()))
                        || ("tcp".equals(cpe.getVendor()) && "tcp".equals(cpe.getProduct()))
                        || ("ssh".equals(cpe.getVendor()) && "ssh".equals(cpe.getProduct()))
                        || ("lookup".equals(cpe.getVendor()) && "lookup".equals(cpe.getProduct())))
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
                        || dependency.getFileName().toLowerCase().endsWith(".rpm")
                        || dependency.getFileName().toLowerCase().endsWith(".ear")
                        || dependency.getFileName().toLowerCase().endsWith(".war"))) {
                    toRemove.add(i);
                } else if ((("jquery".equals(cpe.getVendor()) && "jquery".equals(cpe.getProduct()))
                        || ("prototypejs".equals(cpe.getVendor()) && "prototype".equals(cpe.getProduct()))
                        || ("yahoo".equals(cpe.getVendor()) && "yui".equals(cpe.getProduct())))
                        && (dependency.getFileName().toLowerCase().endsWith(".jar")
                        || dependency.getFileName().toLowerCase().endsWith("pom.xml")
                        || dependency.getFileName().toLowerCase().endsWith(".dll")
                        || dependency.getFileName().toLowerCase().endsWith(".exe"))) {
                    toRemove.add(i);
                } else if ((("microsoft".equals(cpe.getVendor()) && "excel".equals(cpe.getProduct()))
                        || ("microsoft".equals(cpe.getVendor()) && "word".equals(cpe.getProduct()))
                        || ("microsoft".equals(cpe.getVendor()) && "visio".equals(cpe.getProduct()))
                        || ("microsoft".equals(cpe.getVendor()) && "powerpoint".equals(cpe.getProduct()))
                        || ("microsoft".equals(cpe.getVendor()) && "office".equals(cpe.getProduct()))
                        || ("core_ftp".equals(cpe.getVendor()) && "core_ftp".equals(cpe.getProduct())))
                        && (dependency.getFileName().toLowerCase().endsWith(".jar")
                        || dependency.getFileName().toLowerCase().endsWith(".ear")
                        || dependency.getFileName().toLowerCase().endsWith(".war")
                        || dependency.getFileName().toLowerCase().endsWith("pom.xml"))) {
                    toRemove.add(i);
                } else if (("apache".equals(cpe.getVendor()) && "maven".equals(cpe.getProduct()))
                        && !dependency.getFileName().toLowerCase().matches("maven-core-[\\d.]+\\.jar")) {
                    toRemove.add(i);
                } else if (("m-core".equals(cpe.getVendor()) && "m-core".equals(cpe.getProduct()))) {
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
                        toRemove.add(i);
                    }
                } else if (("jboss".equals(cpe.getVendor()) && "jboss".equals(cpe.getProduct()))
                        && !dependency.getFileName().toLowerCase().matches("jboss-?[\\d.-]+(GA)?\\.jar")) {
                    toRemove.add(i);
                } else if ("java-websocket_project".equals(cpe.getVendor())
                        && "java-websocket".equals(cpe.getProduct())) {
                    boolean found = false;
                    for (Identifier si : dependency.getSoftwareIdentifiers()) {
                        if (si.getValue().toLowerCase().contains("org.java-websocket/java-websocket")) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        toRemove.add(i);
                    }
                }
            }
        }
        toRemove.stream().forEach(dependency::removeVulnerableSoftwareIdentifier);
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
            dependency.getVulnerableSoftwareIdentifiers().stream()
                    .filter((i) -> (i instanceof CpeIdentifier))
                    .map(i -> (CpeIdentifier) i)
                    .forEach((i) -> {
                        final Cpe cpe = i.getCpe();
                        if ("apache".equals(cpe.getVendor()) && "axis".equals(cpe.getProduct())) {
                            identifiersToRemove.add(i);
                        }
                    });
        } else if (fileName != null && fileName.contains("axis")) {
            dependency.getVulnerableSoftwareIdentifiers().stream()
                    .filter((i) -> (i instanceof CpeIdentifier))
                    .map(i -> (CpeIdentifier) i)
                    .forEach((i) -> {
                        final Cpe cpe = i.getCpe();
                        if ("apache".equals(cpe.getVendor()) && "axis2".equals(cpe.getProduct())) {
                            identifiersToRemove.add(i);
                        }
                    });
        }
        identifiersToRemove.forEach(dependency::removeVulnerableSoftwareIdentifier);
    }

    /**
     * There are some known CPE entries, specifically regarding sun and oracle
     * products due to the acquisition and changes in product names, that based
     * on given evidence we can add the related CPE entries to ensure a complete
     * list of CVE entries.
     *
     * @param dependency the dependency being analyzed
     */
    @SuppressWarnings("UnnecessaryParentheses")
    private void addFalseNegativeCPEs(Dependency dependency) {
        final CpeBuilder builder = new CpeBuilder();
        //TODO move this to the hint analyzer
        final List<Identifier> identifiersToAdd = new ArrayList<>();
        dependency.getVulnerableSoftwareIdentifiers().stream()
                .filter((i) -> (i instanceof CpeIdentifier))
                .map(i -> (CpeIdentifier) i)
                .forEach((i) -> {
                    final Cpe cpe = i.getCpe();
                    if ((("oracle".equals(cpe.getVendor())
                            && ("opensso".equals(cpe.getProduct()) || "opensso_enterprise".equals(cpe.getProduct()))))
                            || ("sun".equals(cpe.getVendor())
                            && ("opensso".equals(cpe.getProduct()) || "opensso_enterprise".equals(cpe.getProduct())))) {

                        try {
                            final Cpe newCpe1 = builder.part(Part.APPLICATION).vendor("sun")
                                    .product("opensso_enterprise").version(cpe.getVersion()).build();
                            final Cpe newCpe2 = builder.part(Part.APPLICATION).vendor("oracle")
                                    .product("opensso_enterprise").version(cpe.getVersion()).build();
                            final Cpe newCpe3 = builder.part(Part.APPLICATION).vendor("sun")
                                    .product("opensso").version(cpe.getVersion()).build();
                            final Cpe newCpe4 = builder.part(Part.APPLICATION).vendor("oracle")
                                    .product("opensso").version(cpe.getVersion()).build();
                            final CpeIdentifier newCpeId1 = new CpeIdentifier(newCpe1, i.getConfidence());
                            final CpeIdentifier newCpeId2 = new CpeIdentifier(newCpe2, i.getConfidence());
                            final CpeIdentifier newCpeId3 = new CpeIdentifier(newCpe3, i.getConfidence());
                            final CpeIdentifier newCpeId4 = new CpeIdentifier(newCpe4, i.getConfidence());
                            identifiersToAdd.add(newCpeId1);
                            identifiersToAdd.add(newCpeId2);
                            identifiersToAdd.add(newCpeId3);
                            identifiersToAdd.add(newCpeId4);

                        } catch (CpeValidationException ex) {
                            LOGGER.warn("Unable to add oracle and sun CPEs", ex);
                        }
                    }
                    if ("apache".equals(cpe.getVendor()) && "santuario_xml_security_for_java".equals(cpe.getProduct())) {
                        try {
                            final Cpe newCpe1 = builder.part(Part.APPLICATION).vendor("apache")
                                    .product("xml_security_for_java").version(cpe.getVersion()).build();
                            final CpeIdentifier newCpeId1 = new CpeIdentifier(newCpe1, i.getConfidence());
                            identifiersToAdd.add(newCpeId1);
                        } catch (CpeValidationException ex) {
                            LOGGER.warn("Unable to add apache xml_security_for_java CPE", ex);
                        }
                    }
                });
        identifiersToAdd.forEach(dependency::addVulnerableSoftwareIdentifier);
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
        //Believed to be code that should have been removed several versions ago. This logic
        // incorreclty removes dependencies such as more than half the pom entries in pax-web-jetty-bundle-6.0.7.jar
//        if (dependency.getFileName().toLowerCase().endsWith("pom.xml")
//                || DLL_EXE_FILTER.accept(dependency.getActualFile())) {
//            String parentPath = dependency.getFilePath().toLowerCase();
//            if (parentPath.contains(".jar")) {
//                parentPath = parentPath.substring(0, parentPath.indexOf(".jar") + 4);
//                final Dependency[] dependencies = engine.getDependencies();
//                final Dependency parent = findDependency(parentPath, dependencies);
//                if (parent != null) {
//                    final boolean remove = dependency.getVulnerableSoftwareIdentifiers().stream()
//                            .filter((i) -> (i instanceof CpeIdentifier))
//                            .map(i -> (CpeIdentifier) i)
//                            .anyMatch(i -> parent.getVulnerableSoftwareIdentifiers().stream()
//                                    .filter((p) -> (p instanceof CpeIdentifier))
//                                    .map(p -> (CpeIdentifier) p)
//                                    .anyMatch(p -> !p.equals(i)
//                                    && p.getCpe().getPart().equals(i.getCpe().getPart())
//                                    && p.getCpe().getVendor().equals(i.getCpe().getVendor())
//                                    && p.getCpe().getProduct().equals(i.getCpe().getProduct())));
//                    if (remove) {
//                        engine.removeDependency(dependency);
//                    }
//                }
//            }
//        }
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
}
