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
import java.io.FileInputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import org.owasp.dependencycheck.analyzer.pom.generated.License;
import org.owasp.dependencycheck.analyzer.pom.generated.Model;
import org.owasp.dependencycheck.analyzer.pom.generated.Organization;
import org.owasp.dependencycheck.utils.NonClosingStream;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * Used to load a JAR file and collect information that can be used to determine
 * the associated CPE.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class JarAnalyzer extends AbstractAnalyzer implements Analyzer {

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
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
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
     * The unmarshaller used to parse the pom.xml from a JAR file.
     */
    private Unmarshaller pomUnmarshaller;

    /**
     * Constructs a new JarAnalyzer.
     */
    public JarAnalyzer() {
        try {
            final JAXBContext jaxbContext = JAXBContext.newInstance("org.owasp.dependencycheck.analyzer.pom.generated");
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
     * @return whether or not the specified file extension is supported by this
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
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        boolean addPackagesAsEvidence = false;
        try {
            addPackagesAsEvidence ^= parseManifest(dependency);
            addPackagesAsEvidence ^= analyzePOM(dependency);
            addPackagesAsEvidence ^= Settings.getBoolean(Settings.KEYS.PERFORM_DEEP_SCAN);
            analyzePackageNames(dependency, addPackagesAsEvidence);
        } catch (IOException ex) {
            throw new AnalysisException("Exception occurred reading the JAR file.", ex);
        }
    }

    /**
     * Attempts to find a pom.xml within the JAR file. If found it extracts
     * information and adds it to the evidence. This will attempt to interpolate
     * the strings contained within the pom.properties if one exists.
     *
     * @param dependency the dependency being analyzed.
     * @throws IOException is thrown if there is an error reading the zip file.
     * @throws JAXBException is thrown if there is an error extracting the model
     * (aka pom).
     * @throws AnalysisException is thrown if there is an exception parsing the
     * pom.
     * @return whether or not evidence was added to the dependency
     */
    protected boolean analyzePOM(Dependency dependency) throws IOException, AnalysisException {
        boolean foundSomething = false;
        Properties pomProperties = null;
        List<Model> poms = new ArrayList<Model>();
        FileInputStream fs = null;
        try {
            fs = new FileInputStream(dependency.getActualFilePath());
            final ZipInputStream zin = new ZipInputStream(fs);
            ZipEntry entry = zin.getNextEntry();

            while (entry != null) {
                final String entryName = (new File(entry.getName())).getName().toLowerCase();

                if (!entry.isDirectory() && "pom.xml".equals(entryName)) {
                    final NonClosingStream stream = new NonClosingStream(zin);
                    Model p = null;
                    try {
                        final JAXBElement obj = (JAXBElement) pomUnmarshaller.unmarshal(stream);
                        p = (Model) obj.getValue();
                    } catch (JAXBException ex) {
                        String msg = String.format("Unable to parse POM '%s' in '%s'",
                                entry.getName(), dependency.getFilePath());
                        AnalysisException ax = new AnalysisException(msg, ex);
                        dependency.getAnalysisExceptions().add(ax);
                        Logger.getLogger(JarAnalyzer.class.getName()).log(Level.INFO, msg);
                    }
                    if (p != null) {
                        poms.add(p);
                    }
                    zin.closeEntry();
                } else if (!entry.isDirectory() && "pom.properties".equals(entryName)) {
                    //TODO what if there is more then one pom.properties?
                    // need to find the POM, then look to see if there is a sibling
                    // pom.properties and use those together.
                    if (pomProperties == null) {
                        Reader reader;
                        try {
                            reader = new InputStreamReader(zin, "UTF-8");
                            pomProperties = new Properties();
                            pomProperties.load(reader);
                        } finally {
                            //zin.closeEntry closes the reader
                            //reader.close();
                            zin.closeEntry();
                        }
                    } else {
                        String msg = "JAR file contains multiple pom.properties files - unable to process POM";
                        AnalysisException ax = new AnalysisException(msg);
                        dependency.getAnalysisExceptions().add(ax);
                        Logger.getLogger(JarAnalyzer.class.getName()).log(Level.INFO, msg);
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

        for (Model pom : poms) {
            //group id
            final String groupid = interpolateString(pom.getGroupId(), pomProperties);
            if (groupid != null) {
                foundSomething = true;
                dependency.getVendorEvidence().addEvidence("pom", "groupid", groupid, Evidence.Confidence.HIGH);
                dependency.getProductEvidence().addEvidence("pom", "groupid", groupid, Evidence.Confidence.LOW);
            }
            //artifact id
            final String artifactid = interpolateString(pom.getArtifactId(), pomProperties);
            if (artifactid != null) {
                foundSomething = true;
                dependency.getProductEvidence().addEvidence("pom", "artifactid", artifactid, Evidence.Confidence.HIGH);
            }
            //version
            final String version = interpolateString(pom.getVersion(), pomProperties);
            if (version != null) {
                foundSomething = true;
                dependency.getVersionEvidence().addEvidence("pom", "version", version, Evidence.Confidence.HIGH);
            }
            // org name
            final Organization org = pom.getOrganization();
            if (org != null && org.getName() != null) {
                foundSomething = true;
                final String orgName = interpolateString(org.getName(), pomProperties);
                dependency.getVendorEvidence().addEvidence("pom", "organization name", orgName, Evidence.Confidence.HIGH);
            }
            //pom name
            final String pomName = interpolateString(pom.getName(), pomProperties);
            if (pomName != null) {
                foundSomething = true;
                dependency.getProductEvidence().addEvidence("pom", "name", pomName, Evidence.Confidence.HIGH);
            }

            //Description
            if (pom.getDescription() != null) {
                foundSomething = true;
                final String description = interpolateString(pom.getDescription(), pomProperties);
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
        return foundSomething;
    }

    /**
     * Analyzes the path information of the classes contained within the
     * JarAnalyzer to try and determine possible vendor or product names. If any
     * are found they are stored in the packageVendor and packageProduct
     * hashSets.
     *
     * @param dependency A reference to the dependency.
     * @param addPackagesAsEvidence a flag indicating whether or not package
     * names should be added as evidence.
     * @throws IOException is thrown if there is an error reading the JAR file.
     */
    protected void analyzePackageNames(Dependency dependency, boolean addPackagesAsEvidence)
            throws IOException {

        JarFile jar = null;
        try {
            jar = new JarFile(dependency.getActualFilePath());

            final java.util.Enumeration en = jar.entries();

            final HashMap<String, Integer> level0 = new HashMap<String, Integer>();
            final HashMap<String, Integer> level1 = new HashMap<String, Integer>();
            final HashMap<String, Integer> level2 = new HashMap<String, Integer>();
            final HashMap<String, Integer> level3 = new HashMap<String, Integer>();
            int count = 0;
            while (en.hasMoreElements()) {
                final java.util.jar.JarEntry entry = (java.util.jar.JarEntry) en.nextElement();
                if (entry.getName().endsWith(".class") && entry.getName().contains("/")) {
                    final String[] path = entry.getName().toLowerCase().split("/");

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
            final EvidenceCollection vendor = dependency.getVendorEvidence();
            final EvidenceCollection product = dependency.getProductEvidence();

            for (String s : level0.keySet()) {
                if (!"org".equals(s) && !"com".equals(s)) {
                    vendor.addWeighting(s);
                    product.addWeighting(s);
                    if (addPackagesAsEvidence) {
                        vendor.addEvidence("jar", "package", s, Evidence.Confidence.LOW);
                        product.addEvidence("jar", "package", s, Evidence.Confidence.LOW);
                    }
                }
            }
            for (String s : level1.keySet()) {
                float ratio = level1.get(s);
                ratio /= count;
                if (ratio > 0.5) {
                    final String[] parts = s.split("/");
                    if ("org".equals(parts[0]) || "com".equals(parts[0])) {
                        vendor.addWeighting(parts[1]);
                        if (addPackagesAsEvidence) {
                            vendor.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                        }
                    } else {
                        vendor.addWeighting(parts[0]);
                        product.addWeighting(parts[1]);
                        if (addPackagesAsEvidence) {
                            vendor.addEvidence("jar", "package", parts[0], Evidence.Confidence.LOW);
                            product.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                        }
                    }
                }
            }
            for (String s : level2.keySet()) {
                float ratio = level2.get(s);
                ratio /= count;
                if (ratio > 0.4) {
                    final String[] parts = s.split("/");
                    if ("org".equals(parts[0]) || "com".equals(parts[0])) {
                        vendor.addWeighting(parts[1]);
                        product.addWeighting(parts[2]);
                        if (addPackagesAsEvidence) {
                            vendor.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                            product.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                        }
                    } else {
                        vendor.addWeighting(parts[0]);
                        vendor.addWeighting(parts[1]);
                        product.addWeighting(parts[1]);
                        product.addWeighting(parts[2]);
                        if (addPackagesAsEvidence) {
                            vendor.addEvidence("jar", "package", parts[0], Evidence.Confidence.LOW);
                            vendor.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                            product.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                            product.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                        }
                    }
                }
            }
            for (String s : level3.keySet()) {
                float ratio = level3.get(s);
                ratio /= count;
                if (ratio > 0.3) {
                    final String[] parts = s.split("/");
                    if ("org".equals(parts[0]) || "com".equals(parts[0])) {
                        vendor.addWeighting(parts[1]);
                        vendor.addWeighting(parts[2]);
                        product.addWeighting(parts[2]);
                        product.addWeighting(parts[3]);
                        if (addPackagesAsEvidence) {
                            vendor.addEvidence("jar", "package", parts[1], Evidence.Confidence.LOW);
                            vendor.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                            product.addEvidence("jar", "package", parts[2], Evidence.Confidence.LOW);
                            product.addEvidence("jar", "package", parts[3], Evidence.Confidence.LOW);
                        }
                    } else {
                        vendor.addWeighting(parts[0]);
                        vendor.addWeighting(parts[1]);
                        vendor.addWeighting(parts[2]);
                        product.addWeighting(parts[1]);
                        product.addWeighting(parts[2]);
                        product.addWeighting(parts[3]);
                        if (addPackagesAsEvidence) {
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
        } finally {
            if (jar != null) {
                jar.close();
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
     * @return whether evidence was identified parsing the manifest.
     * @throws IOException if there is an issue reading the JAR file.
     */
    protected boolean parseManifest(Dependency dependency) throws IOException {
        boolean foundSomething = false;
        JarFile jar = null;
        try {
            jar = new JarFile(dependency.getActualFilePath());

            final Manifest manifest = jar.getManifest();
            if (manifest == null) {
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.SEVERE,
                        "Jar file '{0}' does not contain a manifest.",
                        dependency.getFileName());
                return false;
            }
            final Attributes atts = manifest.getMainAttributes();

            final EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
            final EvidenceCollection productEvidence = dependency.getProductEvidence();
            final EvidenceCollection versionEvidence = dependency.getVersionEvidence();

            final String source = "Manifest";

            for (Entry<Object, Object> entry : atts.entrySet()) {
                String key = entry.getKey().toString();
                final String value = atts.getValue(key);
                if (key.equals(Attributes.Name.IMPLEMENTATION_TITLE.toString())) {
                    foundSomething = true;
                    productEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                } else if (key.equals(Attributes.Name.IMPLEMENTATION_VERSION.toString())) {
                    foundSomething = true;
                    versionEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                } else if (key.equals(Attributes.Name.IMPLEMENTATION_VENDOR.toString())) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                } else if (key.equals(Attributes.Name.IMPLEMENTATION_VENDOR_ID.toString())) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                } else if (key.equals(BUNDLE_DESCRIPTION)) {
                    foundSomething = true;
                    productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                    dependency.setDescription(value);
                } else if (key.equals(BUNDLE_NAME)) {
                    foundSomething = true;
                    productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                } else if (key.equals(BUNDLE_VENDOR)) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                } else if (key.equals(BUNDLE_VERSION)) {
                    foundSomething = true;
                    versionEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                } else if (key.equals(Attributes.Name.MAIN_CLASS.toString())) {
                    foundSomething = true;
                    productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                    vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                } else {
                    key = key.toLowerCase();

                    if (!IGNORE_LIST.contains(key)
                            && !key.endsWith("jdk")
                            && !key.contains("lastmodified")
                            && !key.endsWith("package")
                            && !isImportPackage(key, value)) {

                        foundSomething = true;
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
                                final StringTokenizer tokenizer = new StringTokenizer(value, " ");
                                while (tokenizer.hasMoreElements()) {
                                    final String s = tokenizer.nextToken();
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
        } finally {
            if (jar != null) {
                jar.close();
            }
        }
        return foundSomething;
    }

    /**
     * Adds a description to the given dependency.
     *
     * @param d a dependency
     * @param description the description
     */
    private void addDescription(Dependency d, String description) {
        if (d.getDescription() == null) {
            d.setDescription(description);
        }
    }

    /**
     * Adds a license to the given dependency.
     *
     * @param d a dependency
     * @param license the license
     */
    private void addLicense(Dependency d, String license) {
        if (d.getLicense() == null) {
            d.setLicense(license);
        } else if (!d.getLicense().contains(license)) {
            d.setLicense(d.getLicense() + NEWLINE + license);
        }
    }

    /**
     * The initialize method does nothing for this Analyzer.
     */
    public void initialize() {
        //do nothing
    }

    /**
     * The close method does nothing for this Analyzer.
     */
    public void close() {
        //do nothing
    }

    /**
     * A utility function that will interpolate strings based on values given in
     * the properties file. It will also interpolate the strings contained
     * within the properties file so that properties can reference other
     * properties.
     *
     * @param text the string that contains references to properties.
     * @param properties a collection of properties that may be referenced
     * within the text.
     * @return the interpolated text.
     */
    protected String interpolateString(String text, Properties properties) {
        //${project.build.directory}
        if (properties == null || text == null) {
            return text;
        }

        final int pos = text.indexOf("${");
        if (pos < 0) {
            return text;
        }
        final int end = text.indexOf("}");
        if (end < pos) {
            return text;
        }

        final String propName = text.substring(pos + 2, end);
        String propValue = interpolateString(properties.getProperty(propName), properties);
        if (propValue == null) {
            propValue = "";
        }
        final StringBuilder sb = new StringBuilder(propValue.length() + text.length());
        sb.append(text.subSequence(0, pos));
        sb.append(propValue);
        sb.append(text.substring(end + 1));
        return interpolateString(sb.toString(), properties); //yes yes, this should be a loop...
    }

    /**
     * Determines if the key value pair from the manifest is for an "import" type
     * entry for package names.
     * @param key the key from the manifest
     * @param value the value from the manifest
     * @return true or false depending on if it is believed the entry is an "import" entry
     */
    private boolean isImportPackage(String key, String value) {
        final Pattern packageRx = Pattern.compile("^((([a-zA-Z_#\\$0-9]\\.)+)\\s*\\;\\s*)+$");
        if (packageRx.matcher(value).matches()) {
            if (key.contains("import") || key.contains("include")) {
                return true;
            } else {
                return false;
            }
        }
        return false;
    }
}
