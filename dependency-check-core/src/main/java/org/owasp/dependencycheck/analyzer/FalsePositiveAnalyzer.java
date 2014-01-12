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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;

/**
 * This analyzer attempts to remove some well known false positives -
 * specifically regarding the java runtime.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class FalsePositiveAnalyzer extends AbstractAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="All standard implmentation details of Analyzer">
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final Set<String> EXTENSIONS = null;
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "False Positive Analyzer";
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
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        removeJreEntries(dependency);
        removeBadMatches(dependency);
        removeWrongVersionMatches(dependency);
        removeSpuriousCPE(dependency);
        addFalseNegativeCPEs(dependency);
    }

    /**
     * <p>Intended to remove spurious CPE entries. By spurious we mean
     * duplicate, less specific CPE entries.</p>
     * <p>Example:</p>
     * <code>
     * cpe:/a:some-vendor:some-product
     * cpe:/a:some-vendor:some-product:1.5
     * cpe:/a:some-vendor:some-product:1.5.2
     * </code>
     * <p>Should be trimmed to:</p>
     * <code>
     * cpe:/a:some-vendor:some-product:1.5.2
     * </code>
     *
     * @param dependency the dependency being analyzed
     */
    @SuppressWarnings("null")
    private void removeSpuriousCPE(Dependency dependency) {
        final List<Identifier> ids = new ArrayList<Identifier>();
        ids.addAll(dependency.getIdentifiers());
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
                            Logger.getLogger(FalsePositiveAnalyzer.class
                                    .getName()).log(Level.FINE, "currentVersion and nextVersion are both null?");
                        } else if (currentVersion == null && nextVersion != null) {
                            dependency.getIdentifiers().remove(currentId);
                        } else if (nextVersion == null && currentVersion != null) {
                            dependency.getIdentifiers().remove(nextId);
                        } else if (currentVersion.length() < nextVersion.length()) {
                            if (nextVersion.startsWith(currentVersion) || "-".equals(currentVersion)) {
                                dependency.getIdentifiers().remove(currentId);
                            }
                        } else {
                            if (currentVersion.startsWith(nextVersion) || "-".equals(nextVersion)) {
                                dependency.getIdentifiers().remove(nextId);
                            }
                        }
                    }
                }
            }
        }
    }
    /**
     * Regex to identify core java libraries and a few other commonly
     * misidentified ones.
     */
    public static final Pattern CORE_JAVA = Pattern.compile("^cpe:/a:(sun|oracle|ibm):(j2[ems]e|"
            + "java(_platfrom_micro_edition|_runtime_environment|_se|virtual_machine|se_development_kit|fx)?|"
            + "jdk|jre|jsf|jsse)($|:.*)");
    /**
     * Regex to identify core java library files. This is currently incomplete.
     */
    public static final Pattern CORE_FILES = Pattern.compile("^((alt[-])?rt|jsf[-].*|jsse|jfxrt|jfr|jce|javaws|deploy|charsets)\\.jar$");

    /**
     * Removes any CPE entries for the JDK/JRE unless the filename ends with
     * rt.jar
     *
     * @param dependency the dependency to remove JRE CPEs from
     */
    private void removeJreEntries(Dependency dependency) {
        final Set<Identifier> identifiers = dependency.getIdentifiers();
        final Iterator<Identifier> itr = identifiers.iterator();
        while (itr.hasNext()) {
            final Identifier i = itr.next();
            final Matcher coreCPE = CORE_JAVA.matcher(i.getValue());
            final Matcher coreFiles = CORE_FILES.matcher(dependency.getFileName());
            if (coreCPE.matches() && !coreFiles.matches()) {
                itr.remove();
            }

            //replacecd with the regex above.
            //            if (("cpe:/a:sun:java".equals(i.getValue())
            //                    || "cpe:/a:oracle:java".equals(i.getValue())
            //                    || "cpe:/a:ibm:java".equals(i.getValue())
            //                    || "cpe:/a:sun:j2se".equals(i.getValue())
            //                    || "cpe:/a:oracle:j2se".equals(i.getValue())
            //                    || i.getValue().startsWith("cpe:/a:sun:java:")
            //                    || i.getValue().startsWith("cpe:/a:sun:j2se:")
            //                    || i.getValue().startsWith("cpe:/a:sun:java:jre")
            //                    || i.getValue().startsWith("cpe:/a:sun:java:jdk")
            //                    || i.getValue().startsWith("cpe:/a:sun:java_se")
            //                    || i.getValue().startsWith("cpe:/a:oracle:java_se")
            //                    || i.getValue().startsWith("cpe:/a:oracle:java:")
            //                    || i.getValue().startsWith("cpe:/a:oracle:j2se:")
            //                    || i.getValue().startsWith("cpe:/a:oracle:jre")
            //                    || i.getValue().startsWith("cpe:/a:oracle:jdk")
            //                    || i.getValue().startsWith("cpe:/a:ibm:java:"))
            //                    && !dependency.getFileName().toLowerCase().endsWith("rt.jar")) {
            //                itr.remove();
            //            }
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
            Logger.getLogger(FalsePositiveAnalyzer.class.getName()).log(Level.FINEST, null, ex);
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
    private void removeBadMatches(Dependency dependency) {
        final Set<Identifier> identifiers = dependency.getIdentifiers();
        final Iterator<Identifier> itr = identifiers.iterator();

        /* TODO - can we utilize the pom's groupid and artifactId to filter??? most of
         * these are due to low quality data.  Other idea would be to say any CPE
         * found based on LOW confidence evidence should have a different CPE type? (this
         * might be a better solution then just removing the URL for "best-guess" matches).
         */

        //Set<Evidence> groupId = dependency.getVendorEvidence().getEvidence("pom", "groupid");
        //Set<Evidence> artifactId = dependency.getVendorEvidence().getEvidence("pom", "artifactid");

        while (itr.hasNext()) {
            final Identifier i = itr.next();
            //TODO move this startswith expression to a configuration file?
            if ("cpe".equals(i.getType())) {
                if ((i.getValue().matches(".*c\\+\\+.*")
                        || i.getValue().startsWith("cpe:/a:jquery:jquery")
                        || i.getValue().startsWith("cpe:/a:prototypejs:prototype")
                        || i.getValue().startsWith("cpe:/a:yahoo:yui")
                        || i.getValue().startsWith("cpe:/a:file:file")
                        || i.getValue().startsWith("cpe:/a:mozilla:mozilla")
                        || i.getValue().startsWith("cpe:/a:cvs:cvs")
                        || i.getValue().startsWith("cpe:/a:ftp:ftp")
                        || i.getValue().startsWith("cpe:/a:ssh:ssh"))
                        && dependency.getFileName().toLowerCase().endsWith(".jar")) {
                    itr.remove();
                } else if (i.getValue().startsWith("cpe:/a:apache:maven")
                        && !dependency.getFileName().toLowerCase().matches("maven-core-[\\d\\.]+\\.jar")) {
                    itr.remove();
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
        final Set<Identifier> identifiers = dependency.getIdentifiers();
        final Iterator<Identifier> itr = identifiers.iterator();

        final String fileName = dependency.getFileName();
        if (fileName != null && fileName.contains("axis2")) {
            while (itr.hasNext()) {
                final Identifier i = itr.next();
                if ("cpe".equals(i.getType())) {
                    final String cpe = i.getValue();
                    if (cpe != null && (cpe.startsWith("cpe:/a:apache:axis:") || "cpe:/a:apache:axis".equals(cpe))) {
                        itr.remove();
                    }
                }
            }
        } else if (fileName != null && fileName.contains("axis")) {
            while (itr.hasNext()) {
                final Identifier i = itr.next();
                if ("cpe".equals(i.getType())) {
                    final String cpe = i.getValue();
                    if (cpe != null && (cpe.startsWith("cpe:/a:apache:axis2:") || "cpe:/a:apache:axis2".equals(cpe))) {
                        itr.remove();
                    }
                }
            }
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
        final Iterator<Identifier> itr = dependency.getIdentifiers().iterator();
        while (itr.hasNext()) {
            final Identifier i = itr.next();
            if ("cpe".equals(i.getType()) && i.getValue() != null
                    && (i.getValue().startsWith("cpe:/a:oracle:opensso:")
                    || i.getValue().startsWith("cpe:/a:oracle:opensso_enterprise:")
                    || i.getValue().startsWith("cpe:/a:sun:opensso_enterprise:")
                    || i.getValue().startsWith("cpe:/a:sun:opensso:"))) {
                final String newCpe = String.format("cpe:/a:sun:opensso_enterprise:%s", i.getValue().substring(22));
                final String newCpe2 = String.format("cpe:/a:oracle:opensso_enterprise:%s", i.getValue().substring(22));
                final String newCpe3 = String.format("cpe:/a:sun:opensso:%s", i.getValue().substring(22));
                final String newCpe4 = String.format("cpe:/a:oracle:opensso:%s", i.getValue().substring(22));
                try {
                    dependency.addIdentifier("cpe",
                            newCpe,
                            String.format("http://web.nvd.nist.gov/view/vuln/search?cpe=%s", URLEncoder.encode(newCpe, "UTF-8")));
                    dependency.addIdentifier("cpe",
                            newCpe2,
                            String.format("http://web.nvd.nist.gov/view/vuln/search?cpe=%s", URLEncoder.encode(newCpe2, "UTF-8")));
                    dependency.addIdentifier("cpe",
                            newCpe3,
                            String.format("http://web.nvd.nist.gov/view/vuln/search?cpe=%s", URLEncoder.encode(newCpe3, "UTF-8")));
                    dependency.addIdentifier("cpe",
                            newCpe4,
                            String.format("http://web.nvd.nist.gov/view/vuln/search?cpe=%s", URLEncoder.encode(newCpe4, "UTF-8")));
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(FalsePositiveAnalyzer.class
                            .getName()).log(Level.FINE, null, ex);
                }
            }
        }
    }
}
