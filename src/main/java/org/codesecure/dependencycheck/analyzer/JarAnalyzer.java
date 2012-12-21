package org.codesecure.dependencycheck.analyzer;
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

import java.io.File;
import java.io.FileInputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import org.codesecure.dependencycheck.dependency.Dependency;
import org.codesecure.dependencycheck.dependency.Evidence;
import org.codesecure.dependencycheck.dependency.EvidenceCollection;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import org.codesecure.dependencycheck.analyzer.pom.generated.License;
import org.codesecure.dependencycheck.analyzer.pom.generated.Model;
import org.codesecure.dependencycheck.analyzer.pom.generated.Organization;
import org.codesecure.dependencycheck.utils.NonClosingStream;

/**
 *
 * Used to load a JAR file and collect information that can be used to determine
 * the associated CPE.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class JarAnalyzer extends AbstractAnalyzer {

    /**
     * The system independent newline character.
     */
    private static final String NEWLINE = System.getProperty("line.separator");
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
            "builtby",
            "createdby",
            "build-jdk",
            "buildjdk",
            "ant-version",
            "antversion",
            "import-package",
            "export-package",
            "importpackage",
            "exportpackage",
            "sealed",
            "manifest-version",
            "archiver-version",
            "manifestversion",
            "archiverversion",
            "classpath",
            "class-path",
            "tool",
            "bundle-manifestversion",
            "bundlemanifestversion");
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
     * The JAXB Contexts used to unmarshall the pom.xml from a JAR file.
     */
    private JAXBContext jaxbContext = null;
    /**
     * The unmarshaller used to parse the pom.xml from a JAR file.
     */
    private Unmarshaller pomUnmarshaller = null;

    /**
     * Constructs a new JarAnalyzer.
     */
    public JarAnalyzer() {
        try {
            jaxbContext = JAXBContext.newInstance("org.codesecure.dependencycheck.analyzer.pom.generated");
            pomUnmarshaller = jaxbContext.createUnmarshaller();
        } catch (JAXBException ex) { //guess we will just have a null pointer exception later...
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

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
     * @param extension the file extension to test for support.
     * @return whether or not the specified file extension is supported by tihs
     * analyzer.
     */
    public boolean supportsExtension(String extension) {
        return EXTENSIONS.contains(extension);
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
     * Loads a specified JAR file and collects information from the manifest and
     * checksums to identify the correct CPE information.
     *
     * @param dependency the dependency to analyze.
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    public void analyze(Dependency dependency) throws AnalysisException {
        try {
            parseManifest(dependency);
            analyzePackageNames(dependency);
            analyzePOM(dependency);
            addPredefinedData(dependency);
        } catch (IOException ex) {
            throw new AnalysisException("Exception occured reading the JAR file.", ex);
        } catch (JAXBException ex) {
            throw new AnalysisException("Exception occured reading the POM within the JAR file.", ex);
        }

    }

    /**
     * Attempts to find a pom.xml within the JAR file. If found it extracts information
     * and adds it to the evidence. This will attempt to interpolate the strings contained
     * within the pom.properties if one exists.
     *
     * @param dependency the dependency being analyzed.
     * @throws IOException is thrown if there is an error reading the zip file.
     * @throws JAXBException is thrown if there is an error extracting the model (aka pom).
     * @throws AnalysisException is thrown if there is an exception parsing the pom.
     */
    protected void analyzePOM(Dependency dependency) throws IOException, JAXBException, AnalysisException {

        Properties pomProperties = null;
        Model pom = null;
        FileInputStream fs = null;
        try {
            fs = new FileInputStream(dependency.getActualFilePath());
            ZipInputStream zin = new ZipInputStream(fs);
            ZipEntry entry = zin.getNextEntry();

            while (entry != null) {
                String entryName = (new File(entry.getName())).getName().toLowerCase();

                if (!entry.isDirectory() && "pom.xml".equals(entryName)) {
                    if (pom == null) {
                        NonClosingStream stream = new NonClosingStream(zin);
                        JAXBElement obj = (JAXBElement) pomUnmarshaller.unmarshal(stream);
                        pom = (org.codesecure.dependencycheck.analyzer.pom.generated.Model) obj.getValue();
                        zin.closeEntry();
                    } else {
                        throw new AnalysisException("JAR file contains multiple pom.xml files - unable to process POM");
                    }
                } else if (!entry.isDirectory() && "pom.properties".equals(entryName)) {
                    if (pomProperties == null) {
                        Reader reader = new InputStreamReader(zin);
                        pomProperties = new Properties();
                        pomProperties.load(reader);
                        zin.closeEntry();
                    } else {
                        throw new AnalysisException("JAR file contains multiple pom.properties files - unable to process POM");
                    }
                }

                entry = zin.getNextEntry();
            }
        } catch (IOException ex) {
            throw new AnalysisException("Error reading JAR file as zip.", ex);
        } finally {
            if (fs != null) {
                fs.close();
            }
        }

        if (pom != null) {
            //group id
            String groupid = interpolateString(pom.getGroupId(), pomProperties);
            if (groupid != null) {
                dependency.getVendorEvidence().addEvidence("pom", "groupid", groupid, Evidence.Confidence.HIGH);
                dependency.getProductEvidence().addEvidence("pom", "groupid", groupid, Evidence.Confidence.LOW);
            }
            //artifact id
            String artifactid = interpolateString(pom.getArtifactId(), pomProperties);
            if (artifactid != null) {
                dependency.getProductEvidence().addEvidence("pom", "artifactid", artifactid, Evidence.Confidence.HIGH);
            }
            //version
            String version = interpolateString(pom.getVersion(), pomProperties);
            if (version != null) {
                dependency.getVersionEvidence().addEvidence("pom", "version", version, Evidence.Confidence.HIGH);
            }
            // org name
            Organization org = pom.getOrganization();
            if (org != null && org.getName() != null) {
                String orgName = interpolateString(org.getName(), pomProperties);
                dependency.getVendorEvidence().addEvidence("pom", "organization name", orgName, Evidence.Confidence.HIGH);
            }
            //pom name
            String pomName = interpolateString(pom.getName(), pomProperties);
            if (pomName != null) {
                dependency.getProductEvidence().addEvidence("pom", "name", pomName, Evidence.Confidence.HIGH);
            }

            //Description
            if (pom.getDescription() != null) {
                String description = interpolateString(pom.getDescription(), pomProperties);
                dependency.setDescription(description);
                dependency.getProductEvidence().addEvidence("pom", "description", description, Evidence.Confidence.MEDIUM);
                dependency.getVendorEvidence().addEvidence("pom", "description", description, Evidence.Confidence.MEDIUM);
            }

            //license
            if (pom.getLicenses() != null) {
                String license = null;
                for (License lic : pom.getLicenses().getLicense()) {
                    String tmp = null;
                    if (lic.getName() != null) {
                        tmp = interpolateString(lic.getName(), pomProperties);
                    }
                    if (lic.getUrl() != null) {
                        if (tmp == null) {
                            tmp = interpolateString(lic.getUrl(), pomProperties);
                        } else {
                            tmp += ": " + interpolateString(lic.getUrl(), pomProperties);
                        }
                    }
                    if (tmp == null) {
                        continue;
                    }
                    if (license == null) {
                        license = tmp;
                    } else {
                        license += "\n" + tmp;
                    }
                }
                if (license != null) {
                    dependency.setLicense(license);
                }
            }
        }
    }

    /**
     * Analyzes the path information of the classes contained within the
     * JarAnalyzer to try and determine possible vendor or product names. If any
     * are found they are stored in the packageVendor and packageProduct
     * hashSets.
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
     * <p>Reads the manifest from the JAR file and collects the entries. Some
     * key entries are:</p> <ul><li>Implementation Title</li> <li>Implementation
     * Version</li> <li>Implementation Vendor</li> <li>Implementation
     * VendorId</li> <li>Bundle Name</li> <li>Bundle Version</li> <li>Bundle
     * Vendor</li> <li>Bundle Description</li> <li>Main Class</li> </ul>
     * However, all but a handful of specific entries are read in.
     *
     * @param dependency A reference to the dependency.
     * @throws IOException if there is an issue reading the JAR file.
     */
    protected void parseManifest(Dependency dependency) throws IOException {
        JarFile jar = new JarFile(dependency.getActualFilePath());
        Manifest manifest = jar.getManifest();
        if (manifest == null) {
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.SEVERE,
                    "Jar file '{0}' does not contain a manifest.",
                    dependency.getFileName());
            return;
        }
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
                dependency.setDescription(value);
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

                if (!IGNORE_LIST.contains(key) && !key.endsWith("jdk")
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
                    } else if (key.contains("license")) {
                        addLicense(dependency, value);
                    } else {
                        if (key.contains("description")) {
                            addDescription(dependency, value);
                        }
                        productEvidence.addEvidence(source, key, value, Evidence.Confidence.LOW);
                        vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.LOW);
                        if (value.matches(".*\\d.*")) {
                            StringTokenizer tokenizer = new StringTokenizer(value, " ");
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

    private void addDescription(Dependency d, String description) {
        if (d.getDescription() == null) {
            d.setDescription(description);
        }
    }

    private void addLicense(Dependency d, String license) {
        if (d.getLicense() == null) {
            d.setLicense(license);
        } else if (!d.getLicense().contains(license)) {
            d.setLicense(d.getLicense() + NEWLINE + license);
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

    /**
     * A utiltiy function that will interpolate strings based on values given
     * in the properties file. It will also interpolate the strings contained
     * within the properties file so that properties can reference other
     * properties.
     *
     * @param text the string that contains references to properties.
     * @param properties a collection of properties that may be referenced within the text.
     * @return the interpolated text.
     */
    protected String interpolateString(String text, Properties properties) {
        //${project.build.directory}
        if (properties == null || text == null) {
            return text;
        }

        int pos = text.indexOf("${");
        if (pos < 0) {
            return text;
        }
        int end = text.indexOf("}");
        if (end < pos) {
            return text;
        }

        String propName = text.substring(pos + 2, end);
        String propValue = interpolateString(properties.getProperty(propName), properties);
        if (propValue == null) {
            propValue = "";
        }
        StringBuilder sb = new StringBuilder(propValue.length() + text.length());
        sb.append(text.subSequence(0, pos));
        sb.append(propValue);
        sb.append(text.substring(end + 1));
        return interpolateString(sb.toString(), properties); //yes yes, this should be a loop...
    }

    private void addPredefinedData(Dependency dependency) {
        Evidence spring = new Evidence("Manifest",
                "Implementation-Title",
                "Spring Framework",
                Evidence.Confidence.HIGH);

        if (dependency.getProductEvidence().getEvidence().contains(spring)) {
            dependency.getVendorEvidence().addEvidence("a priori", "vendor", "SpringSource", Evidence.Confidence.HIGH);
        }
    }
}
