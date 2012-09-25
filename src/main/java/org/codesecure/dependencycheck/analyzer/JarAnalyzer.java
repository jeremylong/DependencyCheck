package org.codesecure.dependencycheck.analyzer;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import org.codesecure.dependencycheck.dependency.Dependency;
import org.codesecure.dependencycheck.dependency.Evidence;
import org.codesecure.dependencycheck.dependency.EvidenceCollection;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 *
 * Used to load a JAR file and collect information that can be used to determine the associated CPE.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class JarAnalyzer extends AbstractAnalyzer {

    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Jar Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INITIAL;
    /**
     * A list of elements in the manifest to ignore.
     */
    private static final Set<String> IGNORE_LIST = newHashSet(
            "built-by",
            "created-by",
            "license",
            "build-jdk",
            "ant-version",
            "import-package",
            "export-package",
            "sealed",
            "manifest-version",
            "archiver-version",
            "classpath",
            "bundle-manifestversion");
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final Set<String> EXTENSIONS = newHashSet("jar");
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_VERSION = "Bundle-Version"; //: 2.1.2
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_DESCRIPTION = "Bundle-Description"; //: Apache Struts 2
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_NAME = "Bundle-Name"; //: Struts 2 Core
    /**
     * item in some manifest, should be considered medium confidence.
     */
    private static final String BUNDLE_VENDOR = "Bundle-Vendor"; //: Apache Software Foundation

    /**
     * Returns a list of file EXTENSIONS supported by this analyzer.
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    public Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

    /**
     * Returns the name of the analyzer.
     * @return the name of the analyzer.
     */
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns whether or not this analyzer can process the given extension.
     * @param extension the file extension to test for support.
     * @return whether or not the specified file extension is supported by tihs analyzer.
     */
    public boolean supportsExtension(String extension) {
        return EXTENSIONS.contains(extension);
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     * @return the phase that the analyzer is intended to run in.
     */
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * An enumeration to keep track of the characters in a string as it is being
     * read in one character at a time.
     */
    private enum STRING_STATE {

        ALPHA,
        NUMBER,
        PERIOD,
        OTHER
    }

    /**
     * Determines type of the character passed in.
     * @param c a character
     * @return a STRING_STATE representing whether the character is number, alpha, or other.
     */
    private STRING_STATE determineState(char c) {
        if (c >= '0' && c <= '9') {
            return STRING_STATE.NUMBER;
        } else if (c == '.') {
            return STRING_STATE.PERIOD;
        } else if (c >= 'a' && c <= 'z') {
            return STRING_STATE.ALPHA;
        } else {
            return STRING_STATE.OTHER;
        }
    }

    /**
     * Loads a specified JAR file and collects information from the manifest and
     * checksums to identify the correct CPE information.
     *
     * @param dependency the dependency to analyze.
     * @throws AnalysisException is thrown if there is an error reading the JAR file.
     */
    public void analyze(Dependency dependency) throws AnalysisException {
        try {
            parseManifest(dependency);
            analyzePackageNames(dependency);
        } catch (IOException ex) {
            throw new AnalysisException("Exception occured reading the JAR file.", ex);
        }

    }

    /**
     * Analyzes the path information of the classes contained within the JarAnalyzer
     * to try and determine possible vendor or product names. If any are found they are
     * stored in the packageVendor and packageProduct hashSets.
     *
     * @param dependency A reference to the dependency.
     * @throws IOException is thrown if there is an error reading the JAR file.
     */
    protected void analyzePackageNames(Dependency dependency) throws IOException {

        JarFile jar = new JarFile(dependency.getActualFilePath());
        java.util.Enumeration en = jar.entries();

        HashMap<String, Integer> level0 = new HashMap<String, Integer>();
        HashMap<String, Integer> level1 = new HashMap<String, Integer>();
        HashMap<String, Integer> level2 = new HashMap<String, Integer>();
        HashMap<String, Integer> level3 = new HashMap<String, Integer>();
        int count = 0;
        while (en.hasMoreElements()) {
            java.util.jar.JarEntry entry = (java.util.jar.JarEntry) en.nextElement();
            if (entry.getName().endsWith(".class") && entry.getName().contains("/")) {
                String[] path = entry.getName().toLowerCase().split("/");

                if ("java".equals(path[0])
                        || "javax".equals(path[0])
                        || ("com".equals(path[0]) && "sun".equals(path[0]))) {
                    continue;
                }

                count += 1;
                String temp = path[0];
                if (level0.containsKey(temp)) {
                    level0.put(temp, level0.get(temp) + 1);
                } else {
                    level0.put(temp, 1);
                }

                if (path.length > 2) {
                    temp += "/" + path[1];
                    if (level1.containsKey(temp)) {
                        level1.put(temp, level1.get(temp) + 1);
                    } else {
                        level1.put(temp, 1);
                    }
                }
                if (path.length > 3) {
                    temp += "/" + path[2];
                    if (level2.containsKey(temp)) {
                        level2.put(temp, level2.get(temp) + 1);
                    } else {
                        level2.put(temp, 1);
                    }
                }

                if (path.length > 4) {
                    temp += "/" + path[3];
                    if (level3.containsKey(temp)) {
                        level3.put(temp, level3.get(temp) + 1);
                    } else {
                        level3.put(temp, 1);
                    }
                }

            }
        }

        if (count == 0) {
            return;
        }
        EvidenceCollection vendor = dependency.getVendorEvidence();
        EvidenceCollection product = dependency.getProductEvidence();

        for (String s : level0.keySet()) {
            if (!"org".equals(s) && !"com".equals(s)) {
                vendor.addWeighting(s);
                product.addWeighting(s);
                vendor.addEvidence("jar", "package", s, Evidence.Confidence.LOW);
                product.addEvidence("jar", "package", s, Evidence.Confidence.LOW);
            }
        }
        for (String s : level1.keySet()) {
            float ratio = level1.get(s);
            ratio /= count;
            if (ratio > 0.5) {
                String[] parts = s.split("/");
                if ("org".equals(parts[0]) || "com".equals(parts[0])) {
                    vendor.addWeighting(parts[1]);
                    vendor.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                } else {
                    vendor.addWeighting(parts[0]);
                    product.addWeighting(parts[1]);
                    vendor.addEvidence("jar", "package", parts[0], Evidence.Confidence.LOW);
                    product.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                }
            }
        }
        for (String s : level2.keySet()) {
            float ratio = level2.get(s);
            ratio /= count;
            if (ratio > 0.4) {
                String[] parts = s.split("/");
                if ("org".equals(parts[0]) || "com".equals(parts[0])) {
                    vendor.addWeighting(parts[1]);
                    product.addWeighting(parts[2]);
                    vendor.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                    product.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                } else {
                    vendor.addWeighting(parts[0]);
                    vendor.addWeighting(parts[1]);
                    product.addWeighting(parts[1]);
                    product.addWeighting(parts[2]);
                    vendor.addEvidence("jar", "package", parts[0], Evidence.Confidence.LOW);
                    vendor.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                    product.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                    product.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                }
            }
        }
        for (String s : level3.keySet()) {
            float ratio = level3.get(s);
            ratio /= count;
            if (ratio > 0.3) {
                String[] parts = s.split("/");
                if ("org".equals(parts[0]) || "com".equals(parts[0])) {
                    vendor.addWeighting(parts[1]);
                    vendor.addWeighting(parts[2]);
                    product.addWeighting(parts[2]);
                    product.addWeighting(parts[3]);
                    vendor.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                    vendor.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                    product.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                    product.addEvidence("jar", "package", parts[3], Evidence.Confidence.LOW);

                } else {
                    vendor.addWeighting(parts[0]);
                    vendor.addWeighting(parts[1]);
                    vendor.addWeighting(parts[2]);
                    product.addWeighting(parts[1]);
                    product.addWeighting(parts[2]);
                    product.addWeighting(parts[3]);
                    vendor.addEvidence("jar", "package", parts[0], Evidence.Confidence.LOW);
                    vendor.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                    vendor.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                    product.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                    product.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                    product.addEvidence("jar", "package", parts[3], Evidence.Confidence.LOW);
                }
            }
        }
    }

    /**
     * <p>Reads the manifest from the JAR file and collects the entries. Some key entries are:</p>
     * <ul><li>Implementation Title</li>
     *     <li>Implementation Version</li>
     *     <li>Implementation Vendor</li>
     *     <li>Implementation VendorId</li>
     *     <li>Bundle Name</li>
     *     <li>Bundle Version</li>
     *     <li>Bundle Vendor</li>
     *     <li>Bundle Description</li>
     *     <li>Main Class</li>
     * </ul>
     * However, all but a handful of specific entries are read in.
     *
     * @param dependency A reference to the dependency.
     * @throws IOException if there is an issue reading the JAR file.
     */
    protected void parseManifest(Dependency dependency) throws IOException {
        JarFile jar = new JarFile(dependency.getActualFilePath());
        Manifest manifest = jar.getManifest();
        Attributes atts = manifest.getMainAttributes();

        EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
        EvidenceCollection productEvidence = dependency.getProductEvidence();
        EvidenceCollection versionEvidence = dependency.getVersionEvidence();

        String source = "Manifest";

        for (Entry<Object, Object> entry : atts.entrySet()) {
            String key = entry.getKey().toString();
            String value = atts.getValue(key);
            if (key.equals(Attributes.Name.IMPLEMENTATION_TITLE.toString())) {
                productEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
            } else if (key.equals(Attributes.Name.IMPLEMENTATION_VERSION.toString())) {
                versionEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
            } else if (key.equals(Attributes.Name.IMPLEMENTATION_VENDOR.toString())) {
                vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
            } else if (key.equals(Attributes.Name.IMPLEMENTATION_VENDOR_ID.toString())) {
                vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
            } else if (key.equals(BUNDLE_DESCRIPTION)) {
                productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
            } else if (key.equals(BUNDLE_NAME)) {
                productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
            } else if (key.equals(BUNDLE_VENDOR)) {
                vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
            } else if (key.equals(BUNDLE_VERSION)) {
                versionEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
            } else if (key.equals(Attributes.Name.MAIN_CLASS.toString())) {
                productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
            } else {
                key = key.toLowerCase();

                if (!IGNORE_LIST.contains(key) && !key.contains("license") && !key.endsWith("jdk")
                        && !key.contains("lastmodified") && !key.endsWith("package")) {

                    if (key.contains("version")) {
                        versionEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                    } else if (key.contains("title")) {
                        productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                    } else if (key.contains("vendor")) {
                        vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                    } else if (key.contains("name")) {
                        productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                        vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                    } else {
                        productEvidence.addEvidence(source, key, value, Evidence.Confidence.LOW);
                        vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.LOW);
                        if (value.matches(".*\\d.*")) {
                            StringTokenizer tokenizer = new StringTokenizer(value," ");
                            while (tokenizer.hasMoreElements()) {
                                String s = tokenizer.nextToken();
                                if (s.matches("^[0-9.]+$")) {
                                    versionEvidence.addEvidence(source, key, s, Evidence.Confidence.LOW);
                                }
                            }
                            //versionEvidence.addEvidence(source, key, value, Evidence.Confidence.LOW);
                        }
                    }
                }
            }
        }
    }

    /**
     * The initialize method does nothing for this Analyzer
     */
    public void initialize() {
        //do nothing
    }

    /**
     * The close method does nothing for this Analyzer
     */
    public void close() {
        //do nothing
    }
}
