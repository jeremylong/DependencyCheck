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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.jaxb.pom;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.sax.SAXSource;

import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.jaxb.pom.generated.Model;
import org.owasp.dependencycheck.jaxb.pom.generated.Organization;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLFilter;
import org.xml.sax.XMLReader;

/**
 *
 * @author jeremy
 */
public class PomUtils {

    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(PomUtils.class.getName());

    /**
     * The unmarshaller used to parse the pom.xml from a JAR file.
     */
    private Unmarshaller pomUnmarshaller;

    /**
     * Constructs a new POM Utility.
     */
    public PomUtils() {
        try {
            //final JAXBContext jaxbContext = JAXBContext.newInstance("org.owasp.dependencycheck.jaxb.pom.generated");
            final JAXBContext jaxbContext = JAXBContext.newInstance(Model.class);
            pomUnmarshaller = jaxbContext.createUnmarshaller();
        } catch (JAXBException ex) { //guess we will just have a null pointer exception later...
            LOGGER.log(Level.SEVERE, "Unable to load parser. See the log for more details.");
            LOGGER.log(Level.FINE, null, ex);
        }
    }

    /**
     * Reads in the specified POM and converts it to a Model.
     *
     * @param file the pom.xml file
     * @return returns a
     * @throws AnalysisException is thrown if there is an exception extracting or parsing the POM
     * {@link org.owasp.dependencycheck.jaxb.pom.generated.Model} object
     */
    public Model readPom(File file) throws AnalysisException {
        Model model = null;
        try {
            final FileInputStream stream = new FileInputStream(file);
            final InputStreamReader reader = new InputStreamReader(stream, "UTF-8");
            final InputSource xml = new InputSource(reader);
            final SAXSource source = new SAXSource(xml);
            model = readPom(source);
        } catch (SecurityException ex) {
            final String msg = String.format("Unable to parse pom '%s'; invalid signature", file.getPath());
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, "", ex);
            throw new AnalysisException(ex);
        } catch (IOException ex) {
            final String msg = String.format("Unable to parse pom '%s'(IO Exception)", file.getPath());
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, "", ex);
            throw new AnalysisException(ex);
        } catch (Throwable ex) {
            final String msg = String.format("Unexpected error during parsing of the pom '%s'", file.getPath());
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, "", ex);
            throw new AnalysisException(ex);
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
    public Model readPom(SAXSource source) throws AnalysisException {
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
   * Reads in the pom file and adds elements as evidence to the given dependency.
   *
   * @param dependency the dependency being analyzed
   * @param pomFile the pom file to read
   * @throws AnalysisException is thrown if there is an exception parsing the pom
   */
  public void analyzePOM(Dependency dependency, File pomFile) throws AnalysisException {
    final Model pom = this.readPom(pomFile);

    String groupid = pom.getGroupId();
    String parentGroupId = null;

    if (pom.getParent() != null) {
      parentGroupId = pom.getParent().getGroupId();
      if ((groupid == null || groupid.isEmpty()) && parentGroupId != null && !parentGroupId.isEmpty()) {
        groupid = parentGroupId;
      }
    }
    if (groupid != null && !groupid.isEmpty()) {
      dependency.getVendorEvidence().addEvidence("pom", "groupid", groupid, Confidence.HIGHEST);
      dependency.getProductEvidence().addEvidence("pom", "groupid", groupid, Confidence.LOW);
      if (parentGroupId != null && !parentGroupId.isEmpty() && !parentGroupId.equals(groupid)) {
        dependency.getVendorEvidence().addEvidence("pom", "parent-groupid", parentGroupId, Confidence.MEDIUM);
        dependency.getProductEvidence().addEvidence("pom", "parent-groupid", parentGroupId, Confidence.LOW);
      }
    }
    String artifactid = pom.getArtifactId();
    String parentArtifactId = null;
    if (pom.getParent() != null) {
      parentArtifactId = pom.getParent().getArtifactId();
      if ((artifactid == null || artifactid.isEmpty()) && parentArtifactId != null && !parentArtifactId.isEmpty()) {
        artifactid = parentArtifactId;
      }
    }
    if (artifactid != null && !artifactid.isEmpty()) {
      if (artifactid.startsWith("org.") || artifactid.startsWith("com.")) {
        artifactid = artifactid.substring(4);
      }
      dependency.getProductEvidence().addEvidence("pom", "artifactid", artifactid, Confidence.HIGHEST);
      dependency.getVendorEvidence().addEvidence("pom", "artifactid", artifactid, Confidence.LOW);
      if (parentArtifactId != null && !parentArtifactId.isEmpty() && !parentArtifactId.equals(artifactid)) {
        dependency.getProductEvidence().addEvidence("pom", "parent-artifactid", parentArtifactId, Confidence.MEDIUM);
        dependency.getVendorEvidence().addEvidence("pom", "parent-artifactid", parentArtifactId, Confidence.LOW);
      }
    }
    //version
    String version = pom.getVersion();
    String parentVersion = null;
    if (pom.getParent() != null) {
      parentVersion = pom.getParent().getVersion();
      if ((version == null || version.isEmpty()) && parentVersion != null && !parentVersion.isEmpty()) {
        version = parentVersion;
      }
    }
    if (version != null && !version.isEmpty()) {
      dependency.getVersionEvidence().addEvidence("pom", "version", version, Confidence.HIGHEST);
      if (parentVersion != null && !parentVersion.isEmpty() && !parentVersion.equals(version)) {
        dependency.getVersionEvidence().addEvidence("pom", "parent-version", version, Confidence.LOW);
      }
    }

    final Organization org = pom.getOrganization();
    if (org != null) {
      final String orgName = org.getName();
      if (orgName != null && !orgName.isEmpty()) {
        dependency.getVendorEvidence().addEvidence("pom", "organization name", orgName, Confidence.HIGH);
      }
    }
    final String pomName = pom.getName();
    if (pomName != null && !pomName.isEmpty()) {
      dependency.getProductEvidence().addEvidence("pom", "name", pomName, Confidence.HIGH);
      dependency.getVendorEvidence().addEvidence("pom", "name", pomName, Confidence.HIGH);
    }

    if (pom.getDescription() != null) {
      final String description = pom.getDescription();
      if (description != null && !description.isEmpty()) {
        JarAnalyzer.addDescription(dependency, description, "pom", "description");
      }
    }
    JarAnalyzer.extractLicense(pom, null, dependency);
  }
}
