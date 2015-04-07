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
package org.owasp.dependencycheck.xml.pom;

import java.io.File;
import java.io.IOException;
import java.util.jar.JarFile;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 *
 * @author jeremy
 */
public final class PomUtils {

    /**
     * empty private constructor for utility class.
     */
    private PomUtils() {
    }
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(PomUtils.class.getName());

    /**
     * Reads in the specified POM and converts it to a Model.
     *
     * @param file the pom.xml file
     * @return returns a
     * @throws AnalysisException is thrown if there is an exception extracting or parsing the POM
     * {@link org.owasp.dependencycheck.jaxb.pom.generated.Model} object
     */
    public static Model readPom(File file) throws AnalysisException {
        Model model = null;
        try {
            PomParser parser = new PomParser();
            parser.parse(file);
        } catch (PomParseException ex) {
            final String msg = String.format("Unable to parse pom '%s'", file.getPath());
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
     * @param path the path to the pom.xml file within the jar file
     * @param jar the jar file to extract the pom from
     * @return returns a
     * @throws AnalysisException is thrown if there is an exception extracting or parsing the POM
     * {@link org.owasp.dependencycheck.jaxb.pom.generated.Model} object
     */
    public static Model readPom(String path, JarFile jar) throws AnalysisException {
        final ZipEntry entry = jar.getEntry(path);
        Model model = null;
        if (entry != null) { //should never be null
            try {
//                final NonClosingStream stream = new NonClosingStream(jar.getInputStream(entry));
//                final InputStreamReader reader = new InputStreamReader(stream, "UTF-8");
//                final InputSource xml = new InputSource(reader);
//                final SAXSource source = new SAXSource(xml);
                final PomParser parser = new PomParser();
                model = parser.parse(jar.getInputStream(entry));
                LOGGER.fine(String.format("Read POM %s", path));
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
     * Reads in the pom file and adds elements as evidence to the given dependency.
     *
     * @param dependency the dependency being analyzed
     * @param pomFile the pom file to read
     * @throws AnalysisException is thrown if there is an exception parsing the pom
     */
    public static void analyzePOM(Dependency dependency, File pomFile) throws AnalysisException {
        final Model pom = PomUtils.readPom(pomFile);

        String groupid = pom.getGroupId();
        String parentGroupId = null;

        if (pom.getParentGroupId() != null) {
            parentGroupId = pom.getParentGroupId();
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
        if (pom.getParentArtifactId() != null) {
            parentArtifactId = pom.getParentArtifactId();
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
        if (pom.getParentVersion() != null) {
            parentVersion = pom.getParentVersion();
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

        final String orgName = pom.getOrganization();
        if (orgName != null && !orgName.isEmpty()) {
            dependency.getVendorEvidence().addEvidence("pom", "organization name", orgName, Confidence.HIGH);
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
