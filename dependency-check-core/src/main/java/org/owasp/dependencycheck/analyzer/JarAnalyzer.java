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

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
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
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.sax.SAXSource;
import org.jsoup.Jsoup;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.jaxb.pom.MavenNamespaceFilter;
import org.owasp.dependencycheck.jaxb.pom.generated.License;
import org.owasp.dependencycheck.jaxb.pom.generated.Model;
import org.owasp.dependencycheck.jaxb.pom.generated.Organization;
import org.owasp.dependencycheck.jaxb.pom.generated.Parent;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.NonClosingStream;
import org.owasp.dependencycheck.utils.Settings;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLFilter;
import org.xml.sax.XMLReader;

/**
 *
 * Used to load a JAR file and collect information that can be used to determine the associated CPE.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class JarAnalyzer extends AbstractFileTypeAnalyzer {

    //<editor-fold defaultstate="collapsed" desc="Constants and Member Variables">
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(JarAnalyzer.class.getName());
    /**
     * The buffer size to use when extracting files from the archive.
     */
    private static final int BUFFER_SIZE = 4096;
    /**
     * The count of directories created during analysis. This is used for creating temporary directories.
     */
    private static int dirCount = 0;
    /**
     * The system independent newline character.
     */
    private static final String NEWLINE = System.getProperty("line.separator");
    /**
     * A list of values in the manifest to ignore as they only result in false positives.
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
            "dynamicimportpackage",
            "dynamicimport-package",
            "dynamic-importpackage",
            "dynamic-import-package",
            "import-package",
            "ignore-package",
            "export-package",
            "importpackage",
            "ignorepackage",
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
            "include-resource",
            "embed-dependency",
            "ipojo-components",
            "ipojo-extension");
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
            LOGGER.log(Level.SEVERE, "Unable to load parser. See the log for more details.");
            LOGGER.log(Level.FINE, null, ex);
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
    @Override
    public Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

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
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }
    //</editor-fold>

    /**
     * Returns the key used in the properties file to reference the analyzer's enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_JAR_ENABLED;
    }

    /**
     * Loads a specified JAR file and collects information from the manifest and checksums to identify the correct CPE
     * information.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR file.
     */
    @Override
    public void analyzeFileType(Dependency dependency, Engine engine) throws AnalysisException {
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
            final boolean hasPOM = analyzePOM(dependency, classNames, engine);
            final boolean addPackagesAsEvidence = !(hasManifest && hasPOM);
            analyzePackageNames(classNames, dependency, addPackagesAsEvidence);
        } catch (IOException ex) {
            throw new AnalysisException("Exception occurred reading the JAR file.", ex);
        }
    }

    /**
     * Attempts to find a pom.xml within the JAR file. If found it extracts information and adds it to the evidence.
     * This will attempt to interpolate the strings contained within the pom.properties if one exists.
     *
     * @param dependency the dependency being analyzed
     * @param classes a collection of class name information
     * @param engine the analysis engine, used to add additional dependencies
     * @throws AnalysisException is thrown if there is an exception parsing the pom
     * @return whether or not evidence was added to the dependency
     */
    protected boolean analyzePOM(Dependency dependency, ArrayList<ClassNameInformation> classes, Engine engine) throws AnalysisException {
        boolean foundSomething = false;
        final JarFile jar;
        try {
            jar = new JarFile(dependency.getActualFilePath());
        } catch (IOException ex) {
            final String msg = String.format("Unable to read JarFile '%s'.", dependency.getActualFilePath());
            //final AnalysisException ax = new AnalysisException(msg, ex);
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, "", ex);
            return false;
        }
        List<String> pomEntries;
        try {
            pomEntries = retrievePomListing(jar);
        } catch (IOException ex) {
            final String msg = String.format("Unable to read Jar file entries in '%s'.", dependency.getActualFilePath());
            //final AnalysisException ax = new AnalysisException(msg, ex);
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, msg, ex);
            return false;
        }
        if (pomEntries.isEmpty()) {
            return false;
        }
        for (String path : pomEntries) {
            Properties pomProperties = null;
            try {
                pomProperties = retrievePomProperties(path, jar);
            } catch (IOException ex) {
                LOGGER.log(Level.FINEST, "ignore this, failed reading a non-existent pom.properties", ex);
            }
            Model pom = null;
            try {
                if (pomEntries.size() > 1) {
                    //extract POM to its own directory and add it as its own dependency
                    final Dependency newDependency = new Dependency();
                    pom = extractPom(path, jar, newDependency);

                    final String displayPath = String.format("%s%s%s",
                            dependency.getFilePath(),
                            File.separator,
                            path); //.replaceAll("[\\/]", File.separator));
                    final String displayName = String.format("%s%s%s",
                            dependency.getFileName(),
                            File.separator,
                            path); //.replaceAll("[\\/]", File.separator));

                    newDependency.setFileName(displayName);
                    newDependency.setFilePath(displayPath);
                    addPomEvidence(newDependency, pom, pomProperties);
                    engine.getDependencies().add(newDependency);
                    Collections.sort(engine.getDependencies());
                } else {
                    pom = retrievePom(path, jar);
                    foundSomething |= setPomEvidence(dependency, pom, pomProperties, classes);
                }
            } catch (AnalysisException ex) {
                final String msg = String.format("An error occured while analyzing '%s'.", dependency.getActualFilePath());
                LOGGER.log(Level.WARNING, msg);
                LOGGER.log(Level.FINE, "", ex);
            }
        }
        return foundSomething;
    }

    /**
     * Given a path to a pom.xml within a JarFile, this method attempts to load a sibling pom.properties if one exists.
     *
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
     * @param dependency the dependency being analyzed
     * @return returns the POM object
     * @throws AnalysisException is thrown if there is an exception extracting or parsing the POM
     * {@link org.owasp.dependencycheck.jaxb.pom.generated.Model} object
     */
    private Model extractPom(String path, JarFile jar, Dependency dependency) throws AnalysisException {
        InputStream input = null;
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        final File tmpDir = getNextTempDirectory();
        final File file = new File(tmpDir, "pom.xml");
        try {
            final ZipEntry entry = jar.getEntry(path);
            input = jar.getInputStream(entry);
            fos = new FileOutputStream(file);
            bos = new BufferedOutputStream(fos, BUFFER_SIZE);
            int count;
            final byte data[] = new byte[BUFFER_SIZE];
            while ((count = input.read(data, 0, BUFFER_SIZE)) != -1) {
                bos.write(data, 0, count);
            }
            bos.flush();
            dependency.setActualFilePath(file.getAbsolutePath());
        } catch (IOException ex) {
            final String msg = String.format("An error occured reading '%s' from '%s'.", path, dependency.getFilePath());
            LOGGER.warning(msg);
            LOGGER.log(Level.SEVERE, "", ex);
        } finally {
            closeStream(bos);
            closeStream(fos);
            closeStream(input);
        }
        Model model = null;
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            final InputStreamReader reader = new InputStreamReader(fis, "UTF-8");
            final InputSource xml = new InputSource(reader);
            final SAXSource source = new SAXSource(xml);
            model = readPom(source);
        } catch (FileNotFoundException ex) {
            final String msg = String.format("Unable to parse pom '%s' in jar '%s' (File Not Found)", path, jar.getName());
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, "", ex);
            throw new AnalysisException(ex);
        } catch (UnsupportedEncodingException ex) {
            final String msg = String.format("Unable to parse pom '%s' in jar '%s' (IO Exception)", path, jar.getName());
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, "", ex);
            throw new AnalysisException(ex);
        } catch (AnalysisException ex) {
            final String msg = String.format("Unable to parse pom '%s' in jar '%s'", path, jar.getName());
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, "", ex);
            throw ex;
        } finally {
            closeStream(fis);
        }
        return model;
    }

    /**
     * Silently closes an input stream ignoring errors.
     *
     * @param stream an input stream to close
     */
    private void closeStream(InputStream stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException ex) {
                LOGGER.log(Level.FINEST, null, ex);
            }
        }
    }

    /**
     * Silently closes an output stream ignoring errors.
     *
     * @param stream an output stream to close
     */
    private void closeStream(OutputStream stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException ex) {
                LOGGER.log(Level.FINEST, null, ex);
            }
        }
    }

    /**
     * Retrieves the specified POM from a jar file and converts it to a Model.
     *
     * @param path the path to the pom.xml file within the jar file
     * @param jar the jar file to extract the pom from
     * @return returns a
     * @throws AnalysisException is thrown if there is an exception extracting or parsing the POM
     * {@link org.owasp.dependencycheck.jaxb.pom.generated.Model} object
     */
    private Model retrievePom(String path, JarFile jar) throws AnalysisException {
        final ZipEntry entry = jar.getEntry(path);
        Model model = null;
        if (entry != null) { //should never be null
            try {
                final NonClosingStream stream = new NonClosingStream(jar.getInputStream(entry));
                final InputStreamReader reader = new InputStreamReader(stream, "UTF-8");
                final InputSource xml = new InputSource(reader);
                final SAXSource source = new SAXSource(xml);
                model = readPom(source);
            } catch (SecurityException ex) {
                final String msg = String.format("Unable to parse pom '%s' in jar '%s'; invalid signature", path, jar.getName());
                LOGGER.log(Level.WARNING, msg);
                LOGGER.log(Level.FINE, null, ex);
                throw new AnalysisException(ex);
            } catch (IOException ex) {
                final String msg = String.format("Unable to parse pom '%s' in jar '%s' (IO Exception)", path, jar.getName());
                LOGGER.log(Level.WARNING, msg);
                LOGGER.log(Level.FINE, "", ex);
                throw new AnalysisException(ex);
            } catch (Throwable ex) {
                final String msg = String.format("Unexpected error during parsing of the pom '%s' in jar '%s'", path, jar.getName());
                LOGGER.log(Level.WARNING, msg);
                LOGGER.log(Level.FINE, "", ex);
                throw new AnalysisException(ex);
            }
        }
        return model;
    }

    /**
     * Retrieves the specified POM from a jar file and converts it to a Model.
     *
     * @param source the SAXSource input stream to read the POM from
     * @return returns the POM object
     * @throws AnalysisException is thrown if there is an exception extracting or parsing the POM
     * {@link org.owasp.dependencycheck.jaxb.pom.generated.Model} object
     */
    private Model readPom(SAXSource source) throws AnalysisException {
        Model model = null;
        try {
            final XMLFilter filter = new MavenNamespaceFilter();
            final SAXParserFactory spf = SAXParserFactory.newInstance();
            final SAXParser sp = spf.newSAXParser();
            final XMLReader xr = sp.getXMLReader();
            filter.setParent(xr);
            final JAXBElement<Model> el = pomUnmarshaller.unmarshal(source, Model.class);
            model = el.getValue();
        } catch (SecurityException ex) {
            throw new AnalysisException(ex);
        } catch (ParserConfigurationException ex) {
            throw new AnalysisException(ex);
        } catch (SAXException ex) {
            throw new AnalysisException(ex);
        } catch (JAXBException ex) {
            throw new AnalysisException(ex);
        } catch (Throwable ex) {
            throw new AnalysisException(ex);
        }
        return model;
    }

    /**
     * Sets evidence from the pom on the supplied dependency.
     *
     * @param dependency the dependency to set data on
     * @param pom the information from the pom
     * @param pomProperties the pom properties file (null if none exists)
     * @param classes a collection of ClassNameInformation - containing data about the fully qualified class names
     * within the JAR file being analyzed
     * @return true if there was evidence within the pom that we could use; otherwise false
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
            dependency.getVendorEvidence().addEvidence("pom", "groupid", groupid, Confidence.HIGH);
            dependency.getProductEvidence().addEvidence("pom", "groupid", groupid, Confidence.LOW);
            addMatchingValues(classes, groupid, dependency.getVendorEvidence());
            addMatchingValues(classes, groupid, dependency.getProductEvidence());
        }
        String artifactid = interpolateString(pom.getArtifactId(), pomProperties);
        if (artifactid != null && !artifactid.isEmpty()) {
            if (artifactid.startsWith("org.") || artifactid.startsWith("com.")) {
                artifactid = artifactid.substring(4);
            }
            foundSomething = true;
            dependency.getProductEvidence().addEvidence("pom", "artifactid", artifactid, Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("pom", "artifactid", artifactid, Confidence.LOW);
            addMatchingValues(classes, artifactid, dependency.getVendorEvidence());
            addMatchingValues(classes, artifactid, dependency.getProductEvidence());
        }
        //version
        final String version = interpolateString(pom.getVersion(), pomProperties);
        if (version != null && !version.isEmpty()) {
            foundSomething = true;
            dependency.getVersionEvidence().addEvidence("pom", "version", version, Confidence.HIGHEST);
        }
        // org name
        final Organization org = pom.getOrganization();
        if (org != null && org.getName() != null) {
            foundSomething = true;
            final String orgName = interpolateString(org.getName(), pomProperties);
            if (orgName != null && !orgName.isEmpty()) {
                dependency.getVendorEvidence().addEvidence("pom", "organization name", orgName, Confidence.HIGH);
                addMatchingValues(classes, orgName, dependency.getVendorEvidence());
            }
        }
        //pom name
        final String pomName = interpolateString(pom.getName(), pomProperties);
        if (pomName != null && !pomName.isEmpty()) {
            foundSomething = true;
            dependency.getProductEvidence().addEvidence("pom", "name", pomName, Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("pom", "name", pomName, Confidence.HIGH);
            addMatchingValues(classes, pomName, dependency.getVendorEvidence());
            addMatchingValues(classes, pomName, dependency.getProductEvidence());
        }

        //Description
        if (pom.getDescription() != null) {
            foundSomething = true;
            final String description = interpolateString(pom.getDescription(), pomProperties);
            if (description != null && !description.isEmpty()) {
                final String trimmedDescription = addDescription(dependency, description, "pom", "description");
                addMatchingValues(classes, trimmedDescription, dependency.getVendorEvidence());
                addMatchingValues(classes, trimmedDescription, dependency.getProductEvidence());
            }
        }
        extractLicense(pom, pomProperties, dependency);
        return foundSomething;
    }

    /**
     * Analyzes the path information of the classes contained within the JarAnalyzer to try and determine possible
     * vendor or product names. If any are found they are stored in the packageVendor and packageProduct hashSets.
     *
     * @param classNames a list of class names
     * @param dependency a dependency to analyze
     * @param addPackagesAsEvidence a flag indicating whether or not package names should be added as evidence.
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
                    vendor.addEvidence("jar", "package", entry.getKey(), Confidence.LOW);
                }
            }
        }
        for (Map.Entry<String, Integer> entry : productIdentifiers.entrySet()) {
            final float ratio = entry.getValue() / (float) classCount;
            if (ratio > 0.5) {
                product.addWeighting(entry.getKey());
                if (addPackagesAsEvidence && entry.getKey().length() > 1) {
                    product.addEvidence("jar", "package", entry.getKey(), Confidence.LOW);
                }
            }
        }
    }

    /**
     * <p>
     * Reads the manifest from the JAR file and collects the entries. Some vendorKey entries are:</p>
     * <ul><li>Implementation Title</li>
     * <li>Implementation Version</li> <li>Implementation Vendor</li>
     * <li>Implementation VendorId</li> <li>Bundle Name</li> <li>Bundle Version</li> <li>Bundle Vendor</li> <li>Bundle
     * Description</li> <li>Main Class</li> </ul>
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
                    LOGGER.log(Level.INFO,
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
                    productEvidence.addEvidence(source, key, value, Confidence.HIGH);
                    addMatchingValues(classInformation, value, productEvidence);
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VERSION.toString())) {
                    foundSomething = true;
                    versionEvidence.addEvidence(source, key, value, Confidence.HIGH);
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VENDOR.toString())) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Confidence.HIGH);
                    addMatchingValues(classInformation, value, vendorEvidence);
                } else if (key.equalsIgnoreCase(Attributes.Name.IMPLEMENTATION_VENDOR_ID.toString())) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, vendorEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_DESCRIPTION)) {
                    foundSomething = true;
                    addDescription(dependency, value, "manifest", key);
                    //productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, productEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_NAME)) {
                    foundSomething = true;
                    productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                    addMatchingValues(classInformation, value, productEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_VENDOR)) {
                    foundSomething = true;
                    vendorEvidence.addEvidence(source, key, value, Confidence.HIGH);
                    addMatchingValues(classInformation, value, vendorEvidence);
                } else if (key.equalsIgnoreCase(BUNDLE_VERSION)) {
                    foundSomething = true;
                    versionEvidence.addEvidence(source, key, value, Confidence.HIGH);
                } else if (key.equalsIgnoreCase(Attributes.Name.MAIN_CLASS.toString())) {
                    continue;
                    //skipping main class as if this has important information to add
                    // it will be added during class name analysis...  if other fields
                    // have the information from the class name then they will get added...
//                    foundSomething = true;
//                    productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
//                    vendorEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
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
                                versionEvidence.addEvidence(source, key, value, Confidence.LOW);
                            } else {
                                versionEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                            }
                        } else if ("build-id".equals(key)) {
                            int pos = value.indexOf('(');
                            if (pos >= 0) {
                                value = value.substring(0, pos - 1);
                            }
                            pos = value.indexOf('[');
                            if (pos >= 0) {
                                value = value.substring(0, pos - 1);
                            }
                            versionEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                        } else if (key.contains("title")) {
                            productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                            addMatchingValues(classInformation, value, productEvidence);
                        } else if (key.contains("vendor")) {
                            if (key.contains("specification")) {
                                vendorEvidence.addEvidence(source, key, value, Confidence.LOW);
                            } else {
                                vendorEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                                addMatchingValues(classInformation, value, vendorEvidence);
                            }
                        } else if (key.contains("name")) {
                            productEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                            vendorEvidence.addEvidence(source, key, value, Confidence.MEDIUM);
                            addMatchingValues(classInformation, value, vendorEvidence);
                            addMatchingValues(classInformation, value, productEvidence);
                        } else if (key.contains("license")) {
                            addLicense(dependency, value);
                        } else {
                            if (key.contains("description")) {
                                addDescription(dependency, value, "manifest", key);
                            } else {
                                productEvidence.addEvidence(source, key, value, Confidence.LOW);
                                vendorEvidence.addEvidence(source, key, value, Confidence.LOW);
                                addMatchingValues(classInformation, value, vendorEvidence);
                                addMatchingValues(classInformation, value, productEvidence);
                                if (value.matches(".*\\d.*")) {
                                    final StringTokenizer tokenizer = new StringTokenizer(value, " ");
                                    while (tokenizer.hasMoreElements()) {
                                        final String s = tokenizer.nextToken();
                                        if (s.matches("^[0-9.]+$")) {
                                            versionEvidence.addEvidence(source, key, s, Confidence.LOW);
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
     * Adds a description to the given dependency. If the description contains one of the following strings beyond 100
     * characters, then the description used will be trimmed to that position:
     * <ul><li>"such as"</li><li>"like "</li><li>"will use "</li><li>"* uses "</li></ul>
     *
     * @param dependency a dependency
     * @param description the description
     * @param source the source of the evidence
     * @param key the "name" of the evidence
     * @return if the description is trimmed, the trimmed version is returned; otherwise the original description is
     * returned
     */
    private String addDescription(Dependency dependency, String description, String source, String key) {
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
            desc = desc.replaceAll("\\s\\s+", " ");
            final int posSuchAs = desc.toLowerCase().indexOf("such as ", 100);
            final int posLike = desc.toLowerCase().indexOf("like ", 100);
            final int posWillUse = desc.toLowerCase().indexOf("will use ", 100);
            final int posUses = desc.toLowerCase().indexOf(" uses ", 100);
            int pos = -1;
            pos = Math.max(pos, posSuchAs);
            if (pos >= 0 && posLike >= 0) {
                pos = Math.min(pos, posLike);
            } else {
                pos = Math.max(pos, posLike);
            }
            if (pos >= 0 && posWillUse >= 0) {
                pos = Math.min(pos, posWillUse);
            } else {
                pos = Math.max(pos, posWillUse);
            }
            if (pos >= 0 && posUses >= 0) {
                pos = Math.min(pos, posUses);
            } else {
                pos = Math.max(pos, posUses);
            }

            if (pos > 0) {
                final StringBuilder sb = new StringBuilder(pos + 3);
                sb.append(desc.substring(0, pos));
                sb.append("...");
                desc = sb.toString();
            }
            dependency.getProductEvidence().addEvidence(source, key, desc, Confidence.LOW);
            dependency.getVendorEvidence().addEvidence(source, key, desc, Confidence.LOW);
        } else {
            dependency.getProductEvidence().addEvidence(source, key, desc, Confidence.MEDIUM);
            dependency.getVendorEvidence().addEvidence(source, key, desc, Confidence.MEDIUM);
        }
        return desc;
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
     * The parent directory for the individual directories per archive.
     */
    private File tempFileLocation = null;

    /**
     * Initializes the JarAnalyzer.
     *
     * @throws Exception is thrown if there is an exception creating a temporary directory
     */
    @Override
    public void initializeFileTypeAnalyzer() throws Exception {
        final File baseDir = Settings.getTempDirectory();
        if (!baseDir.exists()) {
            if (!baseDir.mkdirs()) {
                final String msg = String.format("Unable to make a temporary folder '%s'", baseDir.getPath());
                throw new AnalysisException(msg);
            }
        }
        tempFileLocation = File.createTempFile("check", "tmp", baseDir);
        if (!tempFileLocation.delete()) {
            final String msg = String.format("Unable to delete temporary file '%s'.", tempFileLocation.getAbsolutePath());
            throw new AnalysisException(msg);
        }
        if (!tempFileLocation.mkdirs()) {
            final String msg = String.format("Unable to create directory '%s'.", tempFileLocation.getAbsolutePath());
            throw new AnalysisException(msg);
        }
    }

    /**
     * Deletes any files extracted from the JAR during analysis.
     */
    @Override
    public void close() {
        if (tempFileLocation != null && tempFileLocation.exists()) {
            LOGGER.log(Level.FINE, "Attempting to delete temporary files");
            final boolean success = FileUtils.delete(tempFileLocation);
            if (!success) {
                LOGGER.log(Level.WARNING,
                        "Failed to delete some temporary files, see the log for more details");
            }
        }
    }

    /**
     * <p>
     * A utility function that will interpolate strings based on values given in the properties file. It will also
     * interpolate the strings contained within the properties file so that properties can reference other
     * properties.</p>
     * <p>
     * <b>Note:</b> if there is no property found the reference will be removed. In other words, if the interpolated
     * string will be replaced with an empty string.
     * </p>
     * <p>
     * Example:</p>
     * <code>
     * Properties p = new Properties();
     * p.setProperty("key", "value");
     * String s = interpolateString("'${key}' and '${nothing}'", p);
     * System.out.println(s);
     * </code>
     * <p>
     * Will result in:</p>
     * <code>
     * 'value' and ''
     * </code>
     *
     * @param text the string that contains references to properties.
     * @param properties a collection of properties that may be referenced within the text.
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
     * Determines if the key value pair from the manifest is for an "import" type entry for package names.
     *
     * @param key the key from the manifest
     * @param value the value from the manifest
     * @return true or false depending on if it is believed the entry is an "import" entry
     */
    private boolean isImportPackage(String key, String value) {
        final Pattern packageRx = Pattern.compile("^([a-zA-Z0-9_#\\$\\*\\.]+\\s*[,;]\\s*)+([a-zA-Z0-9_#\\$\\*\\.]+\\s*)?$");
        final boolean matches = packageRx.matcher(value).matches();
        return matches && (key.contains("import") || key.contains("include") || value.length() > 10);
    }

    /**
     * Cycles through an enumeration of JarEntries, contained within the dependency, and returns a list of the class
     * names. This does not include core Java package names (i.e. java.* or javax.*).
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
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, null, ex);
        } finally {
            if (jar != null) {
                try {
                    jar.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.FINEST, null, ex);
                }
            }
        }
        return classNames;
    }

    /**
     * Cycles through the list of class names and places the package levels 0-3 into the provided maps for vendor and
     * product. This is helpful when analyzing vendor/product as many times this is included in the package name.
     *
     * @param classNames a list of class names
     * @param vendor HashMap of possible vendor names from package names (e.g. owasp)
     * @param product HashMap of possible product names from package names (e.g. dependencycheck)
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
     * Adds an entry to the specified collection and sets the Integer (e.g. the count) to 1. If the entry already exists
     * in the collection then the Integer is incremented by 1.
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
     * Cycles through the collection of class name information to see if parts of the package names are contained in the
     * provided value. If found, it will be added as the HIGHEST confidence evidence because we have more then one
     * source corroborating the value.
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
                    evidence.addEvidence("jar", "package name", key, Confidence.HIGHEST);
                }
            }
        }
    }

    /**
     * Simple check to see if the attribute from a manifest is just a package name.
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
     * Adds evidence from the POM to the dependency. This includes the GAV and in some situations the parent GAV if
     * specified.
     *
     * @param dependency the dependency being analyzed
     * @param pom the POM data
     * @param pomProperties the properties file associated with the pom
     */
    private void addPomEvidence(Dependency dependency, Model pom, Properties pomProperties) {
        if (pom == null) {
            return;
        }
        String groupid = interpolateString(pom.getGroupId(), pomProperties);
        if (groupid != null && !groupid.isEmpty()) {
            if (groupid.startsWith("org.") || groupid.startsWith("com.")) {
                groupid = groupid.substring(4);
            }
            dependency.getVendorEvidence().addEvidence("pom", "groupid", groupid, Confidence.HIGH);
            dependency.getProductEvidence().addEvidence("pom", "groupid", groupid, Confidence.LOW);
        }
        String artifactid = interpolateString(pom.getArtifactId(), pomProperties);
        if (artifactid != null && !artifactid.isEmpty()) {
            if (artifactid.startsWith("org.") || artifactid.startsWith("com.")) {
                artifactid = artifactid.substring(4);
            }
            dependency.getProductEvidence().addEvidence("pom", "artifactid", artifactid, Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("pom", "artifactid", artifactid, Confidence.LOW);
        }
        final String version = interpolateString(pom.getVersion(), pomProperties);
        if (version != null && !version.isEmpty()) {
            dependency.getVersionEvidence().addEvidence("pom", "version", version, Confidence.HIGHEST);
        }

        final Parent parent = pom.getParent(); //grab parent GAV
        if (parent != null) {
            final String parentGroupId = interpolateString(parent.getGroupId(), pomProperties);
            if (parentGroupId != null && !parentGroupId.isEmpty()) {
                if (groupid == null || groupid.isEmpty()) {
                    dependency.getVendorEvidence().addEvidence("pom", "parent.groupid", parentGroupId, Confidence.HIGH);
                } else {
                    dependency.getVendorEvidence().addEvidence("pom", "parent.groupid", parentGroupId, Confidence.MEDIUM);
                }
                dependency.getProductEvidence().addEvidence("pom", "parent.groupid", parentGroupId, Confidence.LOW);
            }
            final String parentArtifactId = interpolateString(parent.getArtifactId(), pomProperties);
            if (parentArtifactId != null && !parentArtifactId.isEmpty()) {
                if (artifactid == null || artifactid.isEmpty()) {
                    dependency.getProductEvidence().addEvidence("pom", "parent.artifactid", parentArtifactId, Confidence.HIGH);
                } else {
                    dependency.getProductEvidence().addEvidence("pom", "parent.artifactid", parentArtifactId, Confidence.MEDIUM);
                }
                dependency.getVendorEvidence().addEvidence("pom", "parent.artifactid", parentArtifactId, Confidence.LOW);
            }
            final String parentVersion = interpolateString(parent.getVersion(), pomProperties);
            if (parentVersion != null && !parentVersion.isEmpty()) {
                if (version == null || version.isEmpty()) {
                    dependency.getVersionEvidence().addEvidence("pom", "parent.version", parentVersion, Confidence.HIGH);
                } else {
                    dependency.getVersionEvidence().addEvidence("pom", "parent.version", parentVersion, Confidence.LOW);
                }
            }
        }
        // org name
        final Organization org = pom.getOrganization();
        if (org != null && org.getName() != null) {
            final String orgName = interpolateString(org.getName(), pomProperties);
            if (orgName != null && !orgName.isEmpty()) {
                dependency.getVendorEvidence().addEvidence("pom", "organization name", orgName, Confidence.HIGH);
            }
        }
        //pom name
        final String pomName = interpolateString(pom.getName(), pomProperties);
        if (pomName != null && !pomName.isEmpty()) {
            dependency.getProductEvidence().addEvidence("pom", "name", pomName, Confidence.HIGH);
            dependency.getVendorEvidence().addEvidence("pom", "name", pomName, Confidence.HIGH);
        }

        //Description
        if (pom.getDescription() != null) {
            final String description = interpolateString(pom.getDescription(), pomProperties);
            if (description != null && !description.isEmpty()) {
                addDescription(dependency, description, "pom", "description");
            }
        }
        extractLicense(pom, pomProperties, dependency);
    }

    /**
     * Extracts the license information from the pom and adds it to the dependency.
     *
     * @param pom the pom object
     * @param pomProperties the properties, used for string interpolation
     * @param dependency the dependency to add license information too
     */
    private void extractLicense(Model pom, Properties pomProperties, Dependency dependency) {
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
    }

    /**
     * Stores information about a class name.
     */
    protected static class ClassNameInformation {

        /**
         * <p>
         * Stores information about a given class name. This class will keep the fully qualified class name and a list
         * of the important parts of the package structure. Up to the first four levels of the package structure are
         * stored, excluding a leading "org" or "com". Example:</p>
         * <code>ClassNameInformation obj = new ClassNameInformation("org.owasp.dependencycheck.analyzer.JarAnalyzer");
         * System.out.println(obj.getName());
         * for (String p : obj.getPackageStructure())
         *     System.out.println(p);
         * </code>
         * <p>
         * Would result in:</p>
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
         * Up to the first four levels of the package structure, excluding a leading "org" or "com".
         */
        private final ArrayList<String> packageStructure = new ArrayList<String>();

        /**
         * Get the value of packageStructure
         *
         * @return the value of packageStructure
         */
        public ArrayList<String> getPackageStructure() {
            return packageStructure;
        }
    }

    /**
     * Retrieves the next temporary directory to extract an archive too.
     *
     * @return a directory
     * @throws AnalysisException thrown if unable to create temporary directory
     */
    private File getNextTempDirectory() throws AnalysisException {
        dirCount += 1;
        final File directory = new File(tempFileLocation, String.valueOf(dirCount));
        //getting an exception for some directories not being able to be created; might be because the directory already exists?
        if (directory.exists()) {
            return getNextTempDirectory();
        }
        if (!directory.mkdirs()) {
            final String msg = String.format("Unable to create temp directory '%s'.", directory.getAbsolutePath());
            throw new AnalysisException(msg);
        }
        return directory;
    }
}
