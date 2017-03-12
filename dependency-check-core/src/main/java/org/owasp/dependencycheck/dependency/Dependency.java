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
package org.owasp.dependencycheck.dependency;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.utils.Checksum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A program dependency. This object is one of the core components within
 * DependencyCheck. It is used to collect information about the dependency in
 * the form of evidence. The Evidence is then used to determine if there are any
 * known, published, vulnerabilities associated with the program dependency.
 *
 * @author Jeremy Long
 */
public class Dependency implements Serializable, Comparable<Dependency> {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 1L;
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Dependency.class);
    /**
     * Used as starting point for generating the value in {@link #hashCode()}.
     */
    private static final int MAGIC_HASH_INIT_VALUE = 3;
    /**
     * Used as a multiplier for generating the value in {@link #hashCode()}.
     */
    private static final int MAGIC_HASH_MULTIPLIER = 47;
    /**
     * The actual file path of the dependency on disk.
     */
    private String actualFilePath;
    /**
     * The file path to display.
     */
    private String filePath;
    /**
     * The file name of the dependency.
     */
    private String fileName;
    /**
     * The package path.
     */
    private String packagePath;
    /**
     * The md5 hash of the dependency.
     */
    private String md5sum;
    /**
     * The SHA1 hash of the dependency.
     */
    private String sha1sum;
    /**
     * A list of Identifiers.
     */
    private Set<Identifier> identifiers;
    /**
     * A collection of vendor evidence.
     */
    private final EvidenceCollection vendorEvidence;
    /**
     * A collection of product evidence.
     */
    private final EvidenceCollection productEvidence;
    /**
     * A collection of version evidence.
     */
    private final EvidenceCollection versionEvidence;
    /**
     * The file name to display in reports.
     */
    private String displayName = null;
    /**
     * A set of identifiers that have been suppressed.
     */
    private Set<Identifier> suppressedIdentifiers;
    /**
     * A set of vulnerabilities that have been suppressed.
     */
    private SortedSet<Vulnerability> suppressedVulnerabilities;
    /**
     * The description of the JAR file.
     */
    private String description;
    /**
     * The license that this dependency uses.
     */
    private String license;
    /**
     * A list of vulnerabilities for this dependency.
     */
    private SortedSet<Vulnerability> vulnerabilities;
    /**
     * A collection of related dependencies.
     */
    private Set<Dependency> relatedDependencies = new TreeSet<>();
    /**
     * A list of projects that reference this dependency.
     */
    private Set<String> projectReferences = new HashSet<>();
    /**
     * A list of available versions.
     */
    private List<String> availableVersions = new ArrayList<>();

    /**
     * Returns the package path.
     *
     * @return the package path
     */
    public String getPackagePath() {
        return packagePath;
    }

    /**
     * Sets the package path.
     *
     * @param packagePath the package path
     */
    public void setPackagePath(String packagePath) {
        this.packagePath = packagePath;
    }

    /**
     * Constructs a new Dependency object.
     */
    public Dependency() {
        vendorEvidence = new EvidenceCollection();
        productEvidence = new EvidenceCollection();
        versionEvidence = new EvidenceCollection();
        identifiers = new TreeSet<>();
        vulnerabilities = new TreeSet<>(new VulnerabilityComparator());
        suppressedIdentifiers = new TreeSet<>();
        suppressedVulnerabilities = new TreeSet<>(new VulnerabilityComparator());
    }

    /**
     * Constructs a new Dependency object.
     *
     * @param file the File to create the dependency object from.
     */
    public Dependency(File file) {
        this();
        this.actualFilePath = file.getAbsolutePath();
        this.filePath = this.actualFilePath;
        this.fileName = file.getName();
        this.packagePath = filePath;
        determineHashes(file);
    }

    /**
     * Returns the file name of the dependency.
     *
     * @return the file name of the dependency
     */
    public String getFileName() {
        return this.fileName;
    }

    /**
     * Returns the file name of the dependency with the backslash escaped for
     * use in JavaScript. This is a complete hack as I could not get the replace
     * to work in the template itself.
     *
     * @return the file name of the dependency with the backslash escaped for
     * use in JavaScript
     */
    public String getFileNameForJavaScript() {
        return this.fileName.replace("\\", "\\\\");
    }

    /**
     * Sets the file name of the dependency.
     *
     * @param fileName the file name of the dependency
     */
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    /**
     * Sets the actual file path of the dependency on disk.
     *
     * @param actualFilePath the file path of the dependency
     */
    public void setActualFilePath(String actualFilePath) {
        this.actualFilePath = actualFilePath;
        if (this.sha1sum == null) {
            final File file = new File(this.actualFilePath);
            determineHashes(file);
        }
    }

    /**
     * Gets the file path of the dependency.
     *
     * @return the file path of the dependency
     */
    public String getActualFilePath() {
        return this.actualFilePath;
    }

    /**
     * Gets a reference to the File object.
     *
     * @return the File object
     */
    public File getActualFile() {
        return new File(this.actualFilePath);
    }

    /**
     * Sets the file path of the dependency.
     *
     * @param filePath the file path of the dependency
     */
    public void setFilePath(String filePath) {
        if (this.packagePath == null || this.packagePath.equals(this.filePath)) {
            this.packagePath = filePath;
        }
        this.filePath = filePath;
    }

    /**
     * Sets the file name to display in reports.
     *
     * @param displayName the name to display
     */
    public void setDisplayFileName(String displayName) {
        this.displayName = displayName;
    }

    /**
     * Returns the file name to display in reports; if no display file name has
     * been set it will default to the actual file name.
     *
     * @return the file name to display
     */
    public String getDisplayFileName() {
        if (displayName == null) {
            return this.fileName;
        }
        return this.displayName;
    }

    /**
     * <p>
     * Gets the file path of the dependency.</p>
     * <p>
     * <b>NOTE:</b> This may not be the actual path of the file on disk. The
     * actual path of the file on disk can be obtained via the
     * getActualFilePath().</p>
     *
     * @return the file path of the dependency
     */
    public String getFilePath() {
        return this.filePath;
    }

    /**
     * Returns the MD5 Checksum of the dependency file.
     *
     * @return the MD5 Checksum
     */
    public String getMd5sum() {
        return this.md5sum;
    }

    /**
     * Sets the MD5 Checksum of the dependency.
     *
     * @param md5sum the MD5 Checksum
     */
    public void setMd5sum(String md5sum) {
        this.md5sum = md5sum;
    }

    /**
     * Returns the SHA1 Checksum of the dependency.
     *
     * @return the SHA1 Checksum
     */
    public String getSha1sum() {
        return this.sha1sum;
    }

    /**
     * Sets the SHA1 Checksum of the dependency.
     *
     * @param sha1sum the SHA1 Checksum
     */
    public void setSha1sum(String sha1sum) {
        this.sha1sum = sha1sum;
    }

    /**
     * Returns a List of Identifiers.
     *
     * @return an ArrayList of Identifiers
     */
    public Set<Identifier> getIdentifiers() {
        return this.identifiers;
    }

    /**
     * Sets a List of Identifiers.
     *
     * @param identifiers A list of Identifiers
     */
    public void setIdentifiers(Set<Identifier> identifiers) {
        this.identifiers = identifiers;
    }

    /**
     * Adds an entry to the list of detected Identifiers for the dependency
     * file.
     *
     * @param type the type of identifier (such as CPE)
     * @param value the value of the identifier
     * @param url the URL of the identifier
     */
    public void addIdentifier(String type, String value, String url) {
        final Identifier i = new Identifier(type, value, url);
        this.identifiers.add(i);
    }

    /**
     * Adds an entry to the list of detected Identifiers for the dependency
     * file.
     *
     * @param type the type of identifier (such as CPE)
     * @param value the value of the identifier
     * @param url the URL of the identifier
     * @param confidence the confidence in the Identifier being accurate
     */
    public void addIdentifier(String type, String value, String url, Confidence confidence) {
        final Identifier i = new Identifier(type, value, url);
        i.setConfidence(confidence);
        this.identifiers.add(i);
    }

    /**
     * Adds the maven artifact as evidence.
     *
     * @param source The source of the evidence
     * @param mavenArtifact The maven artifact
     * @param confidence The confidence level of this evidence
     */
    public void addAsEvidence(String source, MavenArtifact mavenArtifact, Confidence confidence) {
        if (mavenArtifact.getGroupId() != null && !mavenArtifact.getGroupId().isEmpty()) {
            this.getVendorEvidence().addEvidence(source, "groupid", mavenArtifact.getGroupId(), confidence);
        }
        if (mavenArtifact.getArtifactId() != null && !mavenArtifact.getArtifactId().isEmpty()) {
            this.getProductEvidence().addEvidence(source, "artifactid", mavenArtifact.getArtifactId(), confidence);
        }
        if (mavenArtifact.getVersion() != null && !mavenArtifact.getVersion().isEmpty()) {
            this.getVersionEvidence().addEvidence(source, "version", mavenArtifact.getVersion(), confidence);
        }
        if (mavenArtifact.getArtifactUrl() != null && !mavenArtifact.getArtifactUrl().isEmpty()) {
            boolean found = false;
            for (Identifier i : this.getIdentifiers()) {
                if ("maven".equals(i.getType()) && i.getValue().equals(mavenArtifact.toString())) {
                    found = true;
                    i.setConfidence(Confidence.HIGHEST);
                    final String url = "http://search.maven.org/#search|ga|1|1%3A%22" + this.getSha1sum() + "%22";
                    i.setUrl(url);
                    //i.setUrl(mavenArtifact.getArtifactUrl());
                    LOGGER.debug("Already found identifier {}. Confidence set to highest", i.getValue());
                    break;
                }
            }
            if (!found) {
                LOGGER.debug("Adding new maven identifier {}", mavenArtifact);
                this.addIdentifier("maven", mavenArtifact.toString(), mavenArtifact.getArtifactUrl(), Confidence.HIGHEST);
            }
        }
    }

    /**
     * Adds an entry to the list of detected Identifiers for the dependency
     * file.
     *
     * @param identifier the identifier to add
     */
    public void addIdentifier(Identifier identifier) {
        this.identifiers.add(identifier);
    }

    /**
     * Get the value of suppressedIdentifiers.
     *
     * @return the value of suppressedIdentifiers
     */
    public Set<Identifier> getSuppressedIdentifiers() {
        return suppressedIdentifiers;
    }

    /**
     * Set the value of suppressedIdentifiers.
     *
     * @param suppressedIdentifiers new value of suppressedIdentifiers
     */
    public void setSuppressedIdentifiers(Set<Identifier> suppressedIdentifiers) {
        this.suppressedIdentifiers = suppressedIdentifiers;
    }

    /**
     * Adds an identifier to the list of suppressed identifiers.
     *
     * @param identifier an identifier that was suppressed.
     */
    public void addSuppressedIdentifier(Identifier identifier) {
        this.suppressedIdentifiers.add(identifier);
    }

    /**
     * Get the value of suppressedVulnerabilities.
     *
     * @return the value of suppressedVulnerabilities
     */
    public SortedSet<Vulnerability> getSuppressedVulnerabilities() {
        return suppressedVulnerabilities;
    }

    /**
     * Set the value of suppressedVulnerabilities.
     *
     * @param suppressedVulnerabilities new value of suppressedVulnerabilities
     */
    public void setSuppressedVulnerabilities(SortedSet<Vulnerability> suppressedVulnerabilities) {
        this.suppressedVulnerabilities = suppressedVulnerabilities;
    }

    /**
     * Adds a vulnerability to the set of suppressed vulnerabilities.
     *
     * @param vulnerability the vulnerability that was suppressed
     */
    public void addSuppressedVulnerability(Vulnerability vulnerability) {
        this.suppressedVulnerabilities.add(vulnerability);
    }

    /**
     * Returns the evidence used to identify this dependency.
     *
     * @return an EvidenceCollection.
     */
    public EvidenceCollection getEvidence() {
        return EvidenceCollection.merge(this.productEvidence, this.vendorEvidence, this.versionEvidence);
    }

    /**
     * Returns the evidence used to identify this dependency.
     *
     * @return an EvidenceCollection.
     */
    public Set<Evidence> getEvidenceForDisplay() {
        return EvidenceCollection.mergeForDisplay(this.productEvidence, this.vendorEvidence, this.versionEvidence);
    }

    /**
     * Returns the evidence used to identify this dependency.
     *
     * @return an EvidenceCollection.
     */
    public EvidenceCollection getEvidenceUsed() {
        return EvidenceCollection.mergeUsed(this.productEvidence, this.vendorEvidence, this.versionEvidence);
    }

    /**
     * Gets the Vendor Evidence.
     *
     * @return an EvidenceCollection.
     */
    public EvidenceCollection getVendorEvidence() {
        return this.vendorEvidence;
    }

    /**
     * Gets the Product Evidence.
     *
     * @return an EvidenceCollection.
     */
    public EvidenceCollection getProductEvidence() {
        return this.productEvidence;
    }

    /**
     * Gets the Version Evidence.
     *
     * @return an EvidenceCollection.
     */
    public EvidenceCollection getVersionEvidence() {
        return this.versionEvidence;
    }

    /**
     * Get the value of description.
     *
     * @return the value of description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Set the value of description.
     *
     * @param description new value of description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Get the value of license.
     *
     * @return the value of license
     */
    public String getLicense() {
        return license;
    }

    /**
     * Set the value of license.
     *
     * @param license new value of license
     */
    public void setLicense(String license) {
        this.license = license;
    }

    /**
     * Get the list of vulnerabilities.
     *
     * @return the list of vulnerabilities
     */
    public SortedSet<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    /**
     * Set the value of vulnerabilities.
     *
     * @param vulnerabilities new value of vulnerabilities
     */
    public void setVulnerabilities(SortedSet<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    /**
     * Determines the sha1 and md5 sum for the given file.
     *
     * @param file the file to create checksums for
     */
    private void determineHashes(File file) {
        String md5 = null;
        String sha1 = null;
        try {
            md5 = Checksum.getMD5Checksum(file);
            sha1 = Checksum.getSHA1Checksum(file);
        } catch (IOException ex) {
            LOGGER.warn("Unable to read '{}' to determine hashes.", file.getName());
            LOGGER.debug("", ex);
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.warn("Unable to use MD5 or SHA1 checksums.");
            LOGGER.debug("", ex);
        }
        this.setMd5sum(md5);
        this.setSha1sum(sha1);
    }

    /**
     * Adds a vulnerability to the dependency.
     *
     * @param vulnerability a vulnerability outlining a vulnerability.
     */
    public void addVulnerability(Vulnerability vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }

    /**
     * Get the value of {@link #relatedDependencies}. This field is used to
     * collect other dependencies which really represent the same dependency,
     * and may be presented as one item in reports.
     *
     * @return the value of relatedDependencies
     */
    public Set<Dependency> getRelatedDependencies() {
        return relatedDependencies;
    }

    /**
     * Get the value of projectReferences.
     *
     * @return the value of projectReferences
     */
    public Set<String> getProjectReferences() {
        return projectReferences;
    }

    /**
     * Set the value of projectReferences.
     *
     * @param projectReferences new value of projectReferences
     */
    public void setProjectReferences(Set<String> projectReferences) {
        this.projectReferences = projectReferences;
    }

    /**
     * Adds a project reference.
     *
     * @param projectReference a project reference
     */
    public void addProjectReference(String projectReference) {
        this.projectReferences.add(projectReference);
    }

    /**
     * Add a collection of project reference.
     *
     * @param projectReferences a set of project references
     */
    public void addAllProjectReferences(Set<String> projectReferences) {
        this.projectReferences.addAll(projectReferences);
    }

    /**
     * Set the value of relatedDependencies.
     *
     * @param relatedDependencies new value of relatedDependencies
     */
    public void setRelatedDependencies(Set<Dependency> relatedDependencies) {
        this.relatedDependencies = relatedDependencies;
    }

    /**
     * Adds a related dependency. The internal collection is normally a
     * {@link java.util.TreeSet}, which relies on
     * {@link #compareTo(Dependency)}. A consequence of this is that if you
     * attempt to add a dependency with the same file path (modulo character
     * case) as one that is already in the collection, it won't get added.
     *
     * @param dependency a reference to the related dependency
     */
    public void addRelatedDependency(Dependency dependency) {
        if (this == dependency) {
            LOGGER.warn("Attempted to add a circular reference - please post the log file to issue #172 here "
                    + "https://github.com/jeremylong/DependencyCheck/issues/172");
            LOGGER.debug("this: {}", this);
            LOGGER.debug("dependency: {}", dependency);
        } else if (!relatedDependencies.add(dependency)) {
            LOGGER.debug("Failed to add dependency, likely due to referencing the same file as another dependency in the set.");
            LOGGER.debug("this: {}", this);
            LOGGER.debug("dependency: {}", dependency);
        }
    }

    /**
     * Get the value of availableVersions.
     *
     * @return the value of availableVersions
     */
    public List<String> getAvailableVersions() {
        return availableVersions;
    }

    /**
     * Set the value of availableVersions.
     *
     * @param availableVersions new value of availableVersions
     */
    public void setAvailableVersions(List<String> availableVersions) {
        this.availableVersions = availableVersions;
    }

    /**
     * Adds a version to the available version list.
     *
     * @param version the version to add to the list
     */
    public void addAvailableVersion(String version) {
        this.availableVersions.add(version);
    }

    /**
     * Implementation of the Comparable&lt;Dependency&gt; interface. The
     * comparison is solely based on the file path.
     *
     * @param o a dependency to compare
     * @return an integer representing the natural ordering
     */
    @Override
    public int compareTo(Dependency o) {
        return this.getFilePath().compareToIgnoreCase(o.getFilePath());
    }

    /**
     * Implementation of the equals method.
     *
     * @param obj the object to compare
     * @return true if the objects are equal, otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final Dependency other = (Dependency) obj;
        return new EqualsBuilder()
                .appendSuper(super.equals(obj))
                .append(this.actualFilePath, other.actualFilePath)
                .append(this.filePath, other.filePath)
                .append(this.fileName, other.fileName)
                .append(this.packagePath, other.packagePath)
                .append(this.md5sum, other.md5sum)
                .append(this.sha1sum, other.sha1sum)
                .append(this.identifiers, other.identifiers)
                .append(this.vendorEvidence, other.vendorEvidence)
                .append(this.productEvidence, other.productEvidence)
                .append(this.versionEvidence, other.versionEvidence)
                .append(this.description, other.description)
                .append(this.license, other.license)
                .append(this.vulnerabilities, other.vulnerabilities)
                //.append(this.relatedDependencies, other.relatedDependencies)
                .append(this.projectReferences, other.projectReferences)
                .append(this.availableVersions, other.availableVersions)
                .isEquals();
    }

    /**
     * Generates the HashCode.
     *
     * @return the HashCode
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(MAGIC_HASH_INIT_VALUE, MAGIC_HASH_MULTIPLIER)
                .append(actualFilePath)
                .append(filePath)
                .append(fileName)
                .append(md5sum)
                .append(sha1sum)
                .append(identifiers)
                .append(vendorEvidence)
                .append(productEvidence)
                .append(versionEvidence)
                .append(description)
                .append(license)
                .append(vulnerabilities)
                //.append(relatedDependencies)
                .append(projectReferences)
                .append(availableVersions)
                .toHashCode();
    }

    /**
     * Standard toString() implementation showing the filename, actualFilePath,
     * and filePath.
     *
     * @return the string representation of the file
     */
    @Override
    public String toString() {
        return "Dependency{ fileName='" + fileName + "', actualFilePath='" + actualFilePath
                + "', filePath='" + filePath + "', packagePath='" + packagePath + "'}";
    }
}
