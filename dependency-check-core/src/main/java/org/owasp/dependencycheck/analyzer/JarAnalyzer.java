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
import java.util.Map;
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
import org.owasp.dependencycheck.jaxb.pom.MavenNamespaceFilter;
import org.owasp.dependencycheck.jaxb.pom.generated.License;
import org.owasp.dependencycheck.jaxb.pom.generated.Model;
import org.owasp.dependencycheck.jaxb.pom.generated.Organization;
import org.owasp.dependencycheck.utils.NonClosingStream;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLFilter;
import org.xml.sax.XMLReader;

/**
 *
 * Used to load a JAR file and collect information that can be used to determine
 * the associated CPE.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class JarAnalyzer extends AbstractAnalyzer implements Analyzer {

    //<editor-fold defaultstate="collapsed" desc="Constants and Member Variables">
    /**
     * The system independent newline character.
     */
    private static final String NEWLINE = System.getProperty("line.separator");
    /**
     * A list of values in the manifest to ignore as they only result in false
     * positives.
     */
    private static final Set<String> IGNORE_VALUES = newHashSet(
            "Sun Java System Application Server");
    /**
     * A list of elements in the manifest to ignore.
     */
    private static final Set<String> IGNORE_KEYS = newHashSet(
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
     * A pattern to detect HTML within text.
     */
    private static final Pattern HTML_DETECTION_PATTERN = Pattern.compile("\\<[a-z]+.*/?\\>", Pattern.CASE_INSENSITIVE);
    /**
     * The unmarshaller used to parse the pom.xml from a JAR file.
     */
    private Unmarshaller pomUnmarshaller;
    //</editor-fold>

    /**
     * Constructs a new JarAnalyzer.
     */
    public JarAnalyzer() {
        try {
            final JAXBContext jaxbContext = JAXBContext.newInstance("org.owasp.dependencycheck.jaxb.pom.generated");
            pomUnmarshaller = jaxbContext.createUnmarshaller();
        } catch (JAXBException ex) { //guess we will just have a null pointer exception later...
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.SEVERE, "Unable to load parser. See the log for more details.");
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINE, null, ex);
        }
    }
    //<editor-fold defaultstate="collapsed" desc="All standard implmentation details of Analyzer">
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Jar Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final Set<String> EXTENSIONS = newHashSet("jar", "war");

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
    //</editor-fold>

    /**
     * Loads a specified JAR file and collects information from the manifest and
     * checksums to identify the correct CPE information.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            final ArrayList<ClassNameInformation> classNames = collectClassNames(dependency);
            final String fileName = dependency.getFileName().toLowerCase();
            if (classNames.isEmpty()
                    && (fileName.endsWith("-sources.jar")
                    || fileName.endsWith("-javadoc.jar")
                    || fileName.endsWith("-src.jar")
                    || fileName.endsWith("-doc.jar"))) {
                engine.getDependencies().remove(dependency);
            }
            final boolean hasManifest = parseManifest(dependency, classNames);
            final boolean hasPOM = analyzePOM(dependency, classNames);
            final boolean addPackagesAsEvidence = !(hasManifest && hasPOM);
            analyzePackageNames(classNames, dependency, addPackagesAsEvidence);
        } catch (IOException ex) {
            throw new AnalysisException("Exception occurred reading the JAR file.", ex);
        }
    }

    /**
     * Attempts to find a pom.xml within the JAR file. If found it extracts
     * information and adds it to the evidence. This will attempt to interpolate
     * the strings contained within the pom.properties if one exists.
     *
     * @param dependency the dependency being analyzed
     * @param classes a collection of class name information
     * @throws AnalysisException is thrown if there is an exception parsing the
     * pom
     * @return whether or not evidence was added to the dependency
     */
    protected boolean analyzePOM(Dependency dependency, ArrayList<ClassNameInformation> classes) throws AnalysisException {
        boolean foundSomething = false;
        final JarFile jar;
        try {
            jar = new JarFile(dependency.getActualFilePath());
        } catch (IOException ex) {
            final String msg = String.format("Unable to read JarFile '%s'.", dependency.getActualFilePath());
            final AnalysisException ax = new AnalysisException(msg, ex);
            dependency.getAnalysisExceptions().add(ax);
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINE, null, ex);
            return false;
        }
        List<String> pomEntries;
        try {
            pomEntries = retrievePomListing(jar);
        } catch (IOException ex) {
            final String msg = String.format("Unable to read Jar file entries in '%s'.", dependency.getActualFilePath());
            final AnalysisException ax = new AnalysisException(msg, ex);
            dependency.getAnalysisExceptions().add(ax);
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.INFO, msg, ex);
            return false;
        }
        if (pomEntries.isEmpty()) {
            return false;
        }
        if (pomEntries.size() > 1) { //need to sort out which pom we will use
            pomEntries = filterPomEntries(pomEntries, classes);
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
                foundSomething = setPomEvidence(dependency, pom, pomProperties, classes) || foundSomething;
            } catch (AnalysisException ex) {
                dependency.addAnalysisException(ex);
            }
        }
        return foundSomething;
    }

    /**
     * Given a path to a pom.xml within a JarFile, this method attempts to load
     * a sibling pom.properties if one exists.
     *
     * @param path the path to the pom.xml within the JarFile
     * @param jar the JarFile to load the pom.properties from
     * @return a Properties object or null if no pom.properties was found
     * @throws IOException thrown if there is an exception reading the
     * pom.properties
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
     * Searches a JarFile for pom.xml entries and returns a listing of these
     * entries.
     *
     * @param jar the JarFile to search
     * @return a list of pom.xml entries
     * @throws IOException thrown if there is an exception reading a JarEntryf
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
     *
     * @param path the path to the pom.xml file within the jar file
     * @param jar the jar file to extract the pom from
     * @return returns a
     * @throws AnalysisException is thrown if there is an exception extracting
     * or parsing the POM
     * {@link org.owasp.dependencycheck.jaxb.pom.generated.Model} object
     */
    private Model retrievePom(String path, JarFile jar) throws AnalysisException {
        final ZipEntry entry = jar.getEntry(path);
        Model model = null;
        if (entry != null) { //should never be null
            try {
                final XMLFilter filter = new MavenNamespaceFilter();
                final SAXParserFactory spf = SAXParserFactory.newInstance();
                final SAXParser sp = spf.newSAXParser();
                final XMLReader xr = sp.getXMLReader();
                filter.setParent(xr);
                final NonClosingStream stream = new NonClosingStream(jar.getInputStream(entry));
                final InputStreamReader reader = new InputStreamReader(stream, "UTF-8");
                final InputSource xml = new InputSource(reader);
                final SAXSource source = new SAXSource(filter, xml);
                final JAXBElement<Model> el = pomUnmarshaller.unmarshal(source, Model.class);
                model = el.getValue();
            } catch (SecurityException ex) {
                final String msg = String.format("Unable to parse pom '%s' in jar '%s'; invalid signature", path, jar.getName());
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINE, null, ex);
                throw new AnalysisException(ex);
            } catch (ParserConfigurationException ex) {
                final String msg = String.format("Unable to parse pom '%s' in jar '%s' (Parser Configuration Error)", path, jar.getName());
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINE, null, ex);
                throw new AnalysisException(ex);
            } catch (SAXException ex) {
                final String msg = String.format("Unable to parse pom '%s' in jar '%s' (SAX Error)", path, jar.getName());
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINE, null, ex);
                throw new AnalysisException(ex);
            } catch (JAXBException ex) {
                final String msg = String.format("Unable to parse pom '%s' in jar '%s' (JAXB Exception)", path, jar.getName());
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINE, null, ex);
                throw new AnalysisException(ex);
            } catch (IOException ex) {
                final String msg = String.format("Unable to parse pom '%s' in jar '%s' (IO Exception)", path, jar.getName());
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINE, null, ex);
                throw new AnalysisException(ex);
            } catch (Throwable ex) {
                final String msg = String.format("Unexpected error during parsing of the pom '%s' in jar '%s'", path, jar.getName());
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINE, null, ex);
                throw new AnalysisException(ex);
            }
        }
        return model;
    }

    /**
     * Sets evidence from the pom on the supplied dependency.
     *
     * @param dependency the dependency to set data on
     * @param pom the information from the pom
     * @param pomProperties the pom properties file (null if none exists)
     * @param classes a collection of ClassNameInformation - containing data
     * about the fully qualified class names within the JAR file being analyzed
     * @return true if there was evidence within the pom that we could use;
     * otherwise false
     */
    private boolean setPomEvidence(Dependency dependency, Model pom, Properties pomProperties, ArrayList<ClassNameInformation> classes) {
        boolean foundSomething = false;
        if (pom == null) {
            return foundSomething;
        }
        String groupid = interpolateString(pom.getGroupId(), pomProperties);
        if (groupid != null && !groupid.isEmpty()) {
            if (groupid.startsWith("org.") || groupid.startsWith("com.")) {
                groupid = groupid.substring(4);
            }
            foundSomething = true;
            dependency.getVendorEvidence().addEvidence("pom", "groupid", groupid, Evidence.Confidence.HIGH);
            dependency.getProductEvidence().addEvidence("pom", "groupid", groupid, Evidence.Confidence.LOW);
            addMatchingValues(classes, groupid, dependency.getVendorEvidence());
            addMatchingValues(classes, groupid, dependency.getProductEvidence());
        }
        String artifactid = interpolateString(pom.getArtifactId(), pomProperties);
        if (artifactid != null && !artifactid.isEmpty()) {
            if (artifactid.startsWith("org.") || artifactid.startsWith("com.")) {
                artifactid = artifactid.substring(4);
            }
            foundSomething = true;
            dependency.getProductEvidence().addEvidence("pom", "artifactid", artifactid, Evidence.Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("pom", "artifactid", artifactid, Evidence.Confidence.LOW);
            addMatchingValues(classes, artifactid, dependency.getVendorEvidence());
            addMatchingValues(classes, artifactid, dependency.getProductEvidence());
        }
        //version
        final String version = interpolateString(pom.getVersion(), pomProperties);
        if (version != null && !version.isEmpty()) {
            foundSomething = true;
            dependency.getVersionEvidence().addEvidence("pom", "version", version, Evidence.Confidence.HIGHEST);
        }
        // org name
        final Organization org = pom.getOrganization();
        if (org != null && org.getName() != null) {
            foundSomething = true;
            final String orgName = interpolateString(org.getName(), pomProperties);
            if (orgName != null && !orgName.isEmpty()) {
                dependency.getVendorEvidence().addEvidence("pom", "organization name", orgName, Evidence.Confidence.HIGH);
                addMatchingValues(classes, orgName, dependency.getVendorEvidence());
            }
        }
        //pom name
        final String pomName = interpolateString(pom.getName(), pomProperties);
        if (pomName != null && !pomName.isEmpty()) {
            foundSomething = true;
            dependency.getProductEvidence().addEvidence("pom", "name", pomName, Evidence.Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("pom", "name", pomName, Evidence.Confidence.HIGH);
            addMatchingValues(classes, pomName, dependency.getVendorEvidence());
            addMatchingValues(classes, pomName, dependency.getProductEvidence());
        }

        //Description
        if (pom.getDescription() != null) {
            foundSomething = true;
            final String description = interpolateString(pom.getDescription(), pomProperties);
            if (description != null && !description.isEmpty()) {
                addDescription(dependency, description, "pom", "description");
                addMatchingValues(classes, description, dependency.getVendorEvidence());
                addMatchingValues(classes, description, dependency.getProductEvidence());
            }
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
     * @param classNames a list of class names
     * @param dependency a dependency to analyze
     * @param addPackagesAsEvidence a flag indicating whether or not package
     * names should be added as evidence.
     */
    protected void analyzePackageNames(ArrayList<ClassNameInformation> classNames,
            Dependency dependency, boolean addPackagesAsEvidence) {
        final HashMap<String, Integer> vendorIdentifiers = new HashMap<String, Integer>();
        final HashMap<String, Integer> productIdentifiers = new HashMap<String, Integer>();
        analyzeFullyQualifiedClassNames(classNames, vendorIdentifiers, productIdentifiers);

        final int classCount = classNames.size();
        final EvidenceCollection vendor = dependency.getVendorEvidence();
        final EvidenceCollection product = dependency.getProductEvidence();

        for (Map.Entry<String, Integer> entry : vendorIdentifiers.entrySet()) {
            final float ratio = entry.getValue() / (float) classCount;
            if (ratio > 0.5) {
                //TODO remove weighting
                vendor.addWeighting(entry.getKey());
                if (addPackagesAsEvidence && entry.getKey().length() > 1) {
                    vendor.addEvidence("jar", "package", entry.getKey(), Evidence.Confidence.LOW);
                }
            }
        }
        for (Map.Entry<String, Integer> entry : productIdentifiers.entrySet()) {
            final float ratio = entry.getValue() / (float) classCount;
            if (ratio > 0.5) {
                product.addWeighting(entry.getKey());
                if (addPackagesAsEvidence && entry.getKey().length() > 1) {
                    product.addEvidence("jar", "package", entry.getKey(), Evidence.Confidence.LOW);
                }
            }
        }
    }

    /**
     * <p>Reads the manifest from the JAR file and collects the entries. Some
     * vendorKey entries are:</p> <ul><li>Implementation Title</li>
     * <li>Implementation Version</li> <li>Implementation Vendor</li>
     * <li>Implementation VendorId</li> <li>Bundle Name</li> <li>Bundle
     * Version</li> <li>Bundle Vendor</li> <li>Bundle Description</li> <li>Main
     * Class</li> </ul>
     * However, all but a handful of specific entries are read in.
     *
     * @param dependency A reference to the dependency
     * @param classInformation a collection of class information
     * @return whether evidence was identified parsing the manifest
     * @throws IOException if there is an issue reading the JAR file
     */
    protected boolean parseManifest(Dependency dependency, ArrayList<ClassNameInformation> classInformation) throws IOException {
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
                    Logger.getLogger(JarAnalyzer.class.getName()).log(Level.INFO,
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
                if (IGNORE_VALUES.contains(value)) {
                    continue;
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_TITLE.toString())) {
                    foundSomething = true;
                    productEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                    addMatchingValues(classInformation, value, productEvidence);
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VERSION.toString())) {
                    foundSomething = true;
                    versionEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VENDOR.toString())) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                    addMatchingValues(classInformation, value, vendorEvidence);
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VENDOR_ID.toString())) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, vendorEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_DESCRIPTION)) {
                    foundSomething = true;
                    addDescription(dependency, value, "manifest", key);
                    //productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, productEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_NAME)) {
                    foundSomething = true;
                    productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, productEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_VENDOR)) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                    addMatchingValues(classInformation, value, vendorEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_VERSION)) {
                    foundSomething = true;
                    versionEvidence.addEvidence(source, key, value, Evidence.Confidence.HIGH);
                } else if (key.equalsIgnoreCase(Attributes.Name.MAIN_CLASS.toString())) {
                    continue;
                    //skipping main class as if this has important information to add
                    // it will be added during class name analysis...  if other fields
                    // have the information from the class name then they will get added...
//                    foundSomething = true;
//                    productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
//                    vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
//                    addMatchingValues(classInformation, value, vendorEvidence);
//                    addMatchingValues(classInformation, value, productEvidence);
                } else {
                    key = key.toLowerCase();

                    if (!IGNORE_KEYS.contains(key)
                            && !key.endsWith("jdk")
                            && !key.contains("lastmodified")
                            && !key.endsWith("package")
                            && !key.endsWith("classpath")
                            && !key.endsWith("class-path")
                            && !key.endsWith("-scm") //todo change this to a regex?
                            && !key.startsWith("scm-")
                            && !isImportPackage(key, value)
                            && !isPackage(key, value)) {

                        foundSomething = true;
                        if (key.contains("version")) {
                            if (key.contains("specification")) {
                                versionEvidence.addEvidence(source, key, value, Evidence.Confidence.LOW);
                            } else {
                                versionEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                            }

                        } else if (key.contains("title")) {
                            productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                            addMatchingValues(classInformation, value, productEvidence);
                        } else if (key.contains("vendor")) {
                            if (key.contains("specification")) {
                                vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.LOW);
                            } else {
                                vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                                addMatchingValues(classInformation, value, vendorEvidence);
                            }
                        } else if (key.contains("name")) {
                            productEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                            vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.MEDIUM);
                            addMatchingValues(classInformation, value, vendorEvidence);
                            addMatchingValues(classInformation, value, productEvidence);
                        } else if (key.contains("license")) {
                            addLicense(dependency, value);
                        } else {
                            if (key.contains("description")) {
                                addDescription(dependency, value, "manifest", key);
                            } else {
                                productEvidence.addEvidence(source, key, value, Evidence.Confidence.LOW);
                                vendorEvidence.addEvidence(source, key, value, Evidence.Confidence.LOW);
                                addMatchingValues(classInformation, value, vendorEvidence);
                                addMatchingValues(classInformation, value, productEvidence);
                                if (value.matches(".*\\d.*")) {
                                    final StringTokenizer tokenizer = new StringTokenizer(value, " ");
                                    while (tokenizer.hasMoreElements()) {
                                        final String s = tokenizer.nextToken();
                                        if (s.matches("^[0-9.]+$")) {
                                            versionEvidence.addEvidence(source, key, s, Evidence.Confidence.LOW);
                                        }
                                    }
                                }
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
     * @param dependency a dependency
     * @param description the description
     * @param source the source of the evidence
     * @param key the "name" of the evidence
     */
    private void addDescription(Dependency dependency, String description, String source, String key) {
        if (dependency.getDescription() == null) {
            dependency.setDescription(description);
        }
        String desc;
        if (HTML_DETECTION_PATTERN.matcher(description).find()) {
            desc = Jsoup.parse(description).text();
        } else {
            desc = description;
        }
        dependency.setDescription(desc);
        if (desc.length() > 100) {
            final int posSuchAs = desc.toLowerCase().indexOf("such as ", 100);
            final int posLike = desc.toLowerCase().indexOf("like ", 100);
            int pos = -1;
            if (posLike > 0 && posSuchAs > 0) {
                pos = posLike > posSuchAs ? posLike : posSuchAs;
            } else if (posLike > 0) {
                pos = posLike;
            } else if (posSuchAs > 0) {
                pos = posSuchAs;
            }
            String descToUse = desc;
            if (pos > 0) {
                final StringBuilder sb = new StringBuilder(pos + 3);
                sb.append(desc.substring(0, pos));
                sb.append("...");
                descToUse = sb.toString();
            }
            dependency.getProductEvidence().addEvidence(source, key, descToUse, Evidence.Confidence.LOW);
            dependency.getVendorEvidence().addEvidence(source, key, descToUse, Evidence.Confidence.LOW);
        } else {
            dependency.getProductEvidence().addEvidence(source, key, desc, Evidence.Confidence.MEDIUM);
            dependency.getVendorEvidence().addEvidence(source, key, desc, Evidence.Confidence.MEDIUM);
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
     * <p>A utility function that will interpolate strings based on values given
     * in the properties file. It will also interpolate the strings contained
     * within the properties file so that properties can reference other
     * properties.</p>
     * <p><b>Note:</b> if there is no property found the reference will be
     * removed. In other words, if the interpolated string will be replaced with
     * an empty string.
     * </p>
     * <p>Example:</p>
     * <code>
     * Properties p = new Properties();
     * p.setProperty("key", "value");
     * String s = interpolateString("'${key}' and '${nothing}'", p);
     * System.out.println(s);
     * </code>
     * <p>Will result in:</p>
     * <code>
     * 'value' and ''
     * </code>
     *
     * @param text the string that contains references to properties.
     * @param properties a collection of properties that may be referenced
     * within the text.
     * @return the interpolated text.
     */
    protected String interpolateString(String text, Properties properties) {
        Properties props = properties;
        if (text == null) {
            return text;
        }
        if (props == null) {
            props = new Properties();
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
        String propValue = interpolateString(props.getProperty(propName), props);
        if (propValue == null) {
            propValue = "";
        }
        final StringBuilder sb = new StringBuilder(propValue.length() + text.length());
        sb.append(text.subSequence(0, pos));
        sb.append(propValue);
        sb.append(text.substring(end + 1));
        return interpolateString(sb.toString(), props); //yes yes, this should be a loop...
    }

    /**
     * Determines if the key value pair from the manifest is for an "import"
     * type entry for package names.
     *
     * @param key the key from the manifest
     * @param value the value from the manifest
     * @return true or false depending on if it is believed the entry is an
     * "import" entry
     */
    private boolean isImportPackage(String key, String value) {
        final Pattern packageRx = Pattern.compile("^((([a-zA-Z_#\\$0-9]\\.)+)\\s*\\;\\s*)+$");
        if (packageRx.matcher(value).matches()) {
            return (key.contains("import") || key.contains("include"));
        }
        return false;
    }

    /**
     * Cycles through an enumeration of JarEntries, contained within the
     * dependency, and returns a list of the class names. This does not include
     * core Java package names (i.e. java.* or javax.*).
     *
     * @param dependency the dependency being analyzed
     * @return an list of fully qualified class names
     */
    private ArrayList<ClassNameInformation> collectClassNames(Dependency dependency) {
        final ArrayList<ClassNameInformation> classNames = new ArrayList<ClassNameInformation>();
        JarFile jar = null;
        try {
            jar = new JarFile(dependency.getActualFilePath());
            final Enumeration entries = jar.entries();
            while (entries.hasMoreElements()) {
                final JarEntry entry = (JarEntry) entries.nextElement();
                final String name = entry.getName().toLowerCase();
                //no longer stripping "|com\\.sun" - there are some com.sun jar files with CVEs.
                if (name.endsWith(".class") && !name.matches("^javax?\\..*$")) {
                    final ClassNameInformation className = new ClassNameInformation(name.substring(0, name.length() - 6));
                    classNames.add(className);
                }
            }
        } catch (IOException ex) {
            final String msg = String.format("Unable to open jar file '%s'.", dependency.getFileName());
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.WARNING, msg);
            Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINE, null, ex);
        } finally {
            if (jar != null) {
                try {
                    jar.close();
                } catch (IOException ex) {
                    Logger.getLogger(JarAnalyzer.class.getName()).log(Level.FINEST, null, ex);
                }
            }
        }
        return classNames;
    }

    /**
     * Cycles through the list of class names and places the package levels 0-3
     * into the provided maps for vendor and product. This is helpful when
     * analyzing vendor/product as many times this is included in the package
     * name.
     *
     * @param classNames a list of class names
     * @param vendor HashMap of possible vendor names from package names (e.g.
     * owasp)
     * @param product HashMap of possible product names from package names (e.g.
     * dependencycheck)
     */
    private void analyzeFullyQualifiedClassNames(ArrayList<ClassNameInformation> classNames,
            HashMap<String, Integer> vendor, HashMap<String, Integer> product) {
        for (ClassNameInformation entry : classNames) {
            final ArrayList<String> list = entry.getPackageStructure();
            addEntry(vendor, list.get(0));

            if (list.size() == 2) {
                addEntry(product, list.get(1));
            }
            if (list.size() == 3) {
                addEntry(vendor, list.get(1));
                addEntry(product, list.get(1));
                addEntry(product, list.get(2));
            }
            if (list.size() >= 4) {
                addEntry(vendor, list.get(1));
                addEntry(vendor, list.get(2));
                addEntry(product, list.get(1));
                addEntry(product, list.get(2));
                addEntry(product, list.get(3));
            }
        }
    }

    /**
     * Adds an entry to the specified collection and sets the Integer (e.g. the
     * count) to 1. If the entry already exists in the collection then the
     * Integer is incremented by 1.
     *
     * @param collection a collection of strings and their occurrence count
     * @param key the key to add to the collection
     */
    private void addEntry(HashMap<String, Integer> collection, String key) {
        if (collection.containsKey(key)) {
            collection.put(key, collection.get(key) + 1);
        } else {
            collection.put(key, 1);
        }
    }

    /**
     * Cycles through the collection of class name information to see if parts
     * of the package names are contained in the provided value. If found, it
     * will be added as the HIGHEST confidence evidence because we have more
     * then one source corroborating the value.
     *
     * @param classes a collection of class name information
     * @param value the value to check to see if it contains a package name
     * @param evidence the evidence collection to add new entries too
     */
    private void addMatchingValues(ArrayList<ClassNameInformation> classes, String value, EvidenceCollection evidence) {
        if (value == null || value.isEmpty()) {
            return;
        }
        final String text = value.toLowerCase();
        for (ClassNameInformation cni : classes) {
            for (String key : cni.getPackageStructure()) {
                if (text.contains(key)) { //note, package structure elements are already lowercase.
                    evidence.addEvidence("jar", "package name", key, Evidence.Confidence.HIGHEST);
                }
            }
        }
    }

    /**
     * <p><b>This is currently a failed implementation.</b> Part of the issue is
     * I was trying to solve the wrong problem. Instead of multiple POMs being
     * in the JAR to just add information about dependencies - I didn't realize
     * until later that I was looking at an uber-jar (aka fat-jar) that included
     * all of its dependencies.</p>
     * <p>I'm leaving this method in the source tree, entirely commented out
     * until a solution https://github.com/jeremylong/DependencyCheck/issues/11
     * has been implemented.</p>
     * <p>Takes a list of pom entries from a JAR file and attempts to filter it
     * down to the pom related to the jar (rather then the pom entry for a
     * dependency).</p>
     *
     * @param pomEntries a list of pom entries
     * @param classes a list of fully qualified classes from the JAR file
     * @return the list of pom entries that are associated with the jar being
     * analyzed rather then the dependent poms
     */
    private List<String> filterPomEntries(List<String> pomEntries, ArrayList<ClassNameInformation> classes) {
        return pomEntries;
//        final HashMap<String, Integer> usePoms = new HashMap<String, Integer>();
//        final ArrayList<String> possiblePoms = new ArrayList<String>();
//        for (String entry : pomEntries) {
//            //todo validate that the starts with is correct... or does it start with a ./ or /?
//            // is it different on different platforms?
//            if (entry.startsWith("META-INF/maven/")) {
//                //trim the meta-inf/maven and pom.xml...
//                final String pomPath = entry.substring(15, entry.length() - 8).toLowerCase();
//                final String[] parts = pomPath.split("/");
//                if (parts == null || parts.length != 2) { //misplaced pom?
//                    //TODO add logging to FINE
//                    possiblePoms.add(entry);
//                }
//                parts[0] = parts[0].replace('.', '/');
//                parts[1] = parts[1].replace('.', '/');
//                for (ClassNameInformation cni : classes) {
//                    final String name = cni.getName();
//                    if (StringUtils.containsIgnoreCase(name, parts[0])) {
//                        addEntry(usePoms, entry);
//                    }
//                    if (StringUtils.containsIgnoreCase(name, parts[1])) {
//                        addEntry(usePoms, entry);
//                    }
//                }
//            } else { // we have a JAR file with an incorrect POM layout...
//                //TODO add logging to FINE
//                possiblePoms.add(entry);
//            }
//        }
//        List<String> retValue;
//        if (usePoms.isEmpty()) {
//            if (possiblePoms.isEmpty()) {
//                retValue = pomEntries;
//            } else {
//                retValue = possiblePoms;
//            }
//        } else {
//            retValue = new ArrayList<String>();
//            int maxCount = 0;
//            for (Map.Entry<String, Integer> entry : usePoms.entrySet()) {
//                final int current = entry.getValue().intValue();
//                if (current > maxCount) {
//                    maxCount = current;
//                    retValue.clear();
//                    retValue.add(entry.getKey());
//                } else if (current == maxCount) {
//                    retValue.add(entry.getKey());
//                }
//            }
//        }
//        return retValue;
    }

    /**
     * Simple check to see if the attribute from a manifest is just a package
     * name.
     *
     * @param key the key of the value to check
     * @param value the value to check
     * @return true if the value looks like a java package name, otherwise false
     */
    private boolean isPackage(String key, String value) {

        return !key.matches(".*(version|title|vendor|name|license|description).*")
                && value.matches("^([a-zA-Z_][a-zA-Z0-9_\\$]*(\\.[a-zA-Z_][a-zA-Z0-9_\\$]*)*)?$");
    }

    /**
     * Stores information about a class name.
     */
    protected static class ClassNameInformation {

        /**
         * Stores information about a given class name. This class will keep the
         * fully qualified class name and a list of the important parts of the
         * package structure. Up to the first four levels of the package
         * structure are stored, excluding a leading "org" or "com". Example:
         * <code>ClassNameInformation obj = new ClassNameInformation("org.owasp.dependencycheck.analyzer.JarAnalyzer");
         * System.out.println(obj.getName());
         * for (String p : obj.getPackageStructure())
         *     System.out.println(p);
         * </code> Would result in:
         * <code>org.owasp.dependencycheck.analyzer.JarAnalyzer
         * owasp
         * dependencycheck
         * analyzer
         * jaranalyzer</code>
         *
         * @param className a fully qualified class name
         */
        ClassNameInformation(String className) {
            name = className;
            if (name.contains("/")) {
                final String[] tmp = className.toLowerCase().split("/");
                int start = 0;
                int end = 3;
                if ("com".equals(tmp[0]) || "org".equals(tmp[0])) {
                    start = 1;
                    end = 4;
                }
                if (tmp.length <= end) {
                    end = tmp.length - 1;
                }
                for (int i = start; i <= end; i++) {
                    packageStructure.add(tmp[i]);
                }
            } else {
                packageStructure.add(name);
            }
        }
        /**
         * The fully qualified class name.
         */
        private String name;

        /**
         * Get the value of name
         *
         * @return the value of name
         */
        public String getName() {
            return name;
        }

        /**
         * Set the value of name
         *
         * @param name new value of name
         */
        public void setName(String name) {
            this.name = name;
        }
        /**
         * Up to the first four levels of the package structure, excluding a
         * leading "org" or "com".
         */
        private ArrayList<String> packageStructure = new ArrayList<String>();

        /**
         * Get the value of packageStructure
         *
         * @return the value of packageStructure
         */
        public ArrayList<String> getPackageStructure() {
            return packageStructure;
        }
    }
}
