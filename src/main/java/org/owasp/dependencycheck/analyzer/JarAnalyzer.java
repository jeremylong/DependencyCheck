/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.ParserConfigurationException;
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
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.sax.SAXSource;
import org.jsoup.Jsoup;
import org.owasp.dependencycheck.analyzer.pom.MavenNamespaceFilter;
import org.owasp.dependencycheck.analyzer.pom.generated.License;
import org.owasp.dependencycheck.analyzer.pom.generated.Model;
import org.owasp.dependencycheck.analyzer.pom.generated.Organization;
import org.owasp.dependencycheck.utils.NonClosingStream;
import org.owasp.dependencycheck.utils.Settings;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLFilter;
import org.xml.sax.XMLReader;

/**
 *
 * Used to load a JAR file and collect information that can be used to determine
 * the associated CPE.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
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
            "bundlemanifestversion",
            "include-resource");
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
        //todo - catch should be more granular here, one for each call likely
        //todo - think about sources/javadoc jars, should we remove or move to related dependency?
        try {
            final boolean hasManifest = parseManifest(dependency);
            final boolean hasPOM = analyzePOM(dependency);
            final boolean deepScan = Settings.getBoolean(Settings.KEYS.PERFORM_DEEP_SCAN);
            if ((!hasManifest && !hasPOM) || deepScan) {
                addPackagesAsEvidence = true;
            }
            final boolean hasClasses = analyzePackageNames(dependency, addPackagesAsEvidence);
            if (!hasClasses
                    && (dependency.getFileName().toLowerCase().endsWith("-sources.jar")
                    || dependency.getFileName().toLowerCase().endsWith("-javadoc.jar")
                    || dependency.getFileName().toLowerCase().endsWith("-src.jar")
                    || dependency.getFileName().toLowerCase().endsWith("-doc.jar"))) {
                engine.getDependencies().remove(dependency);
            }
        } catch (IOException ex) {
            throw new AnalysisException("Exception occurred reading the JAR file.", ex);
        }
    }
    /**
     * A pattern to detect HTML within text.
     */
    private static final Pattern HTML_DETECTION_PATTERN = Pattern.compile("\\<[a-z]+.*/?\\>", Pattern.CASE_INSENSITIVE);

    /**
     * Attempts to find a pom.xml within the JAR file. If found it extracts
     * information and adds it to the evidence. This will attempt to interpolate
     * the strings contained within the pom.properties if one exists.
     *
     * @param dependency the dependency being analyzed.
     * @throws AnalysisException is thrown if there is an exception parsing the pom.
     * @return whether or not evidence was added to the dependency
     */
    protected boolean analyzePOM(Dependency dependency) throws AnalysisException {
        boolean foundSomething = false;
        final JarFile jar;
        try {
            jar = new JarFile(dependency.getActualFilePath());
        } catch (IOException ex) {
            final String msg = String.format("Unable to read JarFile '%s'.", dependency.getActualFilePath());
            final AnalysisException ax = new AnalysisException(msg, ex);
            dependency.getAnalysisExceptions().add(ax);
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg, ex);
            return foundSomething;
        }
        List<String> pomEntries;
        try {
            pomEntries = retrievePomListing(jar);
        } catch (IOException ex) {
            final String msg = String.format("Unable to read JarEntries in '%s'.", dependency.getActualFilePath());
            final AnalysisException ax = new AnalysisException(msg, ex);
            dependency.getAnalysisExceptions().add(ax);
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg, ex);
            return foundSomething;
        }

        for (String path : pomEntries) {
            Properties pomProperties = null;
            try {
                pomProperties = retrievePomProperties(path, jar);
            } catch (IOException ex) {
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINEST, "ignore this, failed reading a non-existent pom.properties", ex);
            }
            Model pom = null;
            try {
                pom = retrievePom(path, jar);
            } catch (JAXBException ex) {
                final String msg = String.format("Unable to parse POM '%s' in '%s'",
                        path, dependency.getFilePath());
                final AnalysisException ax = new AnalysisException(msg, ex);
                dependency.getAnalysisExceptions().add(ax);
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.SEVERE, msg, ax);
            } catch (IOException ex) {
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
            }
            foundSomething = setPomEvidence(dependency, pom, pomProperties) || foundSomething;
        }
        return foundSomething;
    }

    /**
     * Given a path to a pom.xml within a JarFile, this method attempts to load
     * a sibling pom.properties if one exists.
     * @param path the path to the pom.xml within the JarFile
     * @param jar the JarFile to load the pom.properties from
     * @return a Properties object or null if no pom.properties was found
     * @throws IOException thrown if there is an exception reading the pom.properties
     */
    @edu.umd.cs.findbugs.annotations.SuppressWarnings(value = "OS_OPEN_STREAM",
    justification = "The reader is closed by closing the zipEntry")
    private Properties retrievePomProperties(String path, final JarFile jar) throws IOException {
        Properties pomProperties = null;
        final String propPath = path.substring(0, path.length() - 7) + "pom.properies";
        final ZipEntry propEntry = jar.getEntry(propPath);
        if (propEntry != null) {
            final Reader reader = new InputStreamReader(jar.getInputStream(propEntry), "UTF-8");
            pomProperties = new Properties();
            pomProperties.load(reader);
        }
        return pomProperties;
    }
    /**
     * Searches a JarFile for pom.xml entries and returns a listing of these entries.
     * @param jar the JarFile to search
     * @return a list of pom.xml entries
     * @throws IOException thrown if there is an exception reading a JarEntry
     */
    private List<String> retrievePomListing(final JarFile jar) throws IOException {
        final List<String> pomEntries = new ArrayList<String>();
        final Enumeration<JarEntry> entries = jar.entries();
        while (entries.hasMoreElements()) {
            final JarEntry entry = entries.nextElement();
            final String entryName = (new File(entry.getName())).getName().toLowerCase();
                if (!entry.isDirectory() && "pom.xml".equals(entryName)) {
                    pomEntries.add(entry.getName());
                }
        }
        return pomEntries;
    }
    /**
     * Retrieves the specified POM from a jar file and converts it to a Model.
     * @param path the path to the pom.xml file within the jar file
     * @param jar the jar file to extract the pom from
     * @return returns a {@link org.owasp.dependencycheck.analyzer.pom.generated.Model} object
     * @throws JAXBException is thrown if there is an exception parsing the pom
     * @throws IOException is thrown if there is an exception reading the jar
     */
    private Model retrievePom(String path, JarFile jar) throws JAXBException, IOException {
        final ZipEntry entry = jar.getEntry(path);
        if (entry != null) { //should never be null
            Model m = null;
            try {
                final XMLFilter filter = new MavenNamespaceFilter();
                final SAXParserFactory spf = SAXParserFactory.newInstance();
                final SAXParser sp = spf.newSAXParser();
                final XMLReader xr = sp.getXMLReader();
                filter.setParent(xr);
                final NonClosingStream stream = new NonClosingStream(jar.getInputStream(entry));
                final InputStreamReader reader = new InputStreamReader(stream);
                final InputSource xml = new InputSource(reader);
                final SAXSource source = new SAXSource(filter, xml);
                final JAXBElement<Model> el = pomUnmarshaller.unmarshal(source, Model.class);
                m = el.getValue();
            } catch (ParserConfigurationException ex) {
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SAXException ex) {
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
            } catch (JAXBException ex) {
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINEST, "failure reading pom via jaxb path:'"
                        + path + "' jar:'" + jar.getName() + "'", ex);
            }

            return m;
        }
        return null;
    }

    /**
     * Sets evidence from the pom on the supplied dependency.
     * @param dependency the dependency to set data on
     * @param pom the information from the pom
     * @param pomProperties the pom properties file (null if none exists)
     * @return true if there was evidence within the pom that we could use; otherwise false
     */
    private boolean setPomEvidence(Dependency dependency, Model pom, Properties pomProperties) {
        boolean foundSomething = false;
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
            dependency.getVendorEvidence().addEvidence("pom", "artifactid", artifactid, Evidence.Confidence.LOW);
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
            dependency.getVendorEvidence().addEvidence("pom", "name", pomName, Evidence.Confidence.HIGH);
        }

        //Description
        if (pom.getDescription() != null) {
            foundSomething = true;
            String description = interpolateString(pom.getDescription(), pomProperties);

            if (HTML_DETECTION_PATTERN.matcher(description).find()) {
                description = Jsoup.parse(description).text();
            }

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
                if (HTML_DETECTION_PATTERN.matcher(tmp).find()) {
                    tmp = Jsoup.parse(tmp).text();
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
     * @return returns true or false depending on whether classes were identified in the JAR
     * @throws IOException is thrown if there is an error reading the JAR file.
     */
    protected boolean analyzePackageNames(Dependency dependency, boolean addPackagesAsEvidence)
            throws IOException {
        JarFile jar = null;
        try {
            jar = new JarFile(dependency.getActualFilePath());
            final Enumeration en = jar.entries();
            final HashMap<String, Integer> level0 = new HashMap<String, Integer>();
            final HashMap<String, Integer> level1 = new HashMap<String, Integer>();
            final HashMap<String, Integer> level2 = new HashMap<String, Integer>();
            final HashMap<String, Integer> level3 = new HashMap<String, Integer>();
            final int count = collectPackageNameInformation(en, level0, level1, level2, level3);

            if (count == 0) {
                return false;
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
        return true;
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
                //don't log this for javadoc or sources jar files
                if (!dependency.getFileName().toLowerCase().endsWith("-sources.jar")
                        && !dependency.getFileName().toLowerCase().endsWith("-javadoc.jar")
                        && !dependency.getFileName().toLowerCase().endsWith("-src.jar")
                        && !dependency.getFileName().toLowerCase().endsWith("-doc.jar")) {
                    Logger.getLogger(JarAnalyzer.class.getName()).log(Level.SEVERE,
                            String.format("Jar file '%s' does not contain a manifest.",
                            dependency.getFileName()));
                }
                return false;
            }
            final Attributes atts = manifest.getMainAttributes();

            final EvidenceCollection vendorEvidence = dependency.getVendorEvidence();
            final EvidenceCollection productEvidence = dependency.getProductEvidence();
            final EvidenceCollection versionEvidence = dependency.getVersionEvidence();

            final String source = "Manifest";

            for (Entry<Object, Object> entry : atts.entrySet()) {
                String key = entry.getKey().toString();
                String value = atts.getValue(key);
                if (HTML_DETECTION_PATTERN.matcher(value).find()) {
                    value = Jsoup.parse(value).text();
                }
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
                            && !key.endsWith("classpath")
                            && !key.endsWith("class-path")
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
            return (key.contains("import") || key.contains("include"));
        }
        return false;
    }

    /**
     * Cycles through an enumeration of JarEntries and collects level 0-3 directory
     * structure names. This is helpful when analyzing vendor/product as many times
     * this is included in the package name. This does not analyze core Java package
     * names.
     *
     * @param en an Enumeration of JarEntries
     * @param level0 HashMap of level 0 package names (e.g. org)
     * @param level1 HashMap of level 1 package names (e.g. owasp)
     * @param level2 HashMap of level 2 package names (e.g. dependencycheck)
     * @param level3 HashMap of level 3 package names (e.g. analyzer)
     * @return the number of entries processed that were included in the above HashMaps
     */
    private int collectPackageNameInformation(Enumeration en, HashMap<String, Integer> level0,
            HashMap<String, Integer> level1, HashMap<String, Integer> level2, HashMap<String, Integer> level3) {
        int count = 0;
        while (en.hasMoreElements()) {
            final JarEntry entry = (JarEntry) en.nextElement();
            if (entry.getName().endsWith(".class")) {
                String[] path;
                if (entry.getName().contains("/")) {
                    path = entry.getName().toLowerCase().split("/");
                    if ("java".equals(path[0])
                            || "javax".equals(path[0])
                            || ("com".equals(path[0]) && "sun".equals(path[0]))) {
                        continue;
                    }
                } else {
                    path = new String[1];
                    path[0] = entry.getName();
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
        return count;
    }
}
