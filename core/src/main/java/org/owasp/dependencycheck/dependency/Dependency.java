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

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.utils.Checksum;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * A program dependency. This object is one of the core components within
 * DependencyCheck. It is used to collect information about the dependency in
 * the form of evidence. The Evidence is then used to determine if there are any
 * known, published, vulnerabilities associated with the program dependency.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class Dependency extends EvidenceCollection implements Serializable {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 1L;
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Dependency.class);
    /**
     * The MD5 hashing function.
     */
    private static final HashingFunction MD5_HASHING_FUNCTION = new HashingFunction() {
        @Override
        public String hash(File file) throws IOException, NoSuchAlgorithmException {
            return Checksum.getMD5Checksum(file);
        }
    };
    /**
     * The SHA1 hashing function.
     */
    private static final HashingFunction SHA1_HASHING_FUNCTION = new HashingFunction() {
        @Override
        public String hash(File file) throws IOException, NoSuchAlgorithmException {
            return Checksum.getSHA1Checksum(file);
        }
    };
    /**
     * The SHA256 hashing function.
     */
    private static final HashingFunction SHA256_HASHING_FUNCTION = new HashingFunction() {
        @Override
        public String hash(File file) throws IOException, NoSuchAlgorithmException {
            return Checksum.getSHA256Checksum(file);
        }
    };
    /**
     * A list of Identifiers.
     */
    private final Set<Identifier> identifiers = new TreeSet<>();
    /**
     * A set of identifiers that have been suppressed.
     */
    private final Set<Identifier> suppressedIdentifiers = new TreeSet<>();
    /**
     * A set of vulnerabilities that have been suppressed.
     */
    private final Set<Vulnerability> suppressedVulnerabilities = new HashSet<>();
    /**
     * A list of vulnerabilities for this dependency.
     */
    private final Set<Vulnerability> vulnerabilities = new HashSet<>();
    /**
     * A collection of related dependencies.
     */
    private final Set<Dependency> relatedDependencies = new HashSet<>();
    /**
     * A list of projects that reference this dependency.
     */
    private final Set<String> projectReferences = new HashSet<>();
    /**
     * A list of available versions.
     */
    private final List<String> availableVersions = new ArrayList<>();
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
     * The SHA256 hash of the dependency.
     */
    private String sha256sum;
    /**
     * The file name to display in reports.
     */
    private String displayName = null;
    /**
     * The description of the JAR file.
     */
    private String description;
    /**
     * The license that this dependency uses.
     */
    private String license;
    /**
     * Defines an actual or virtual dependency.
     */
    private boolean isVirtual = false;

    /**
     * Defines the human-recognizable name for the dependency
     */
    private String name;

    /**
     * Defines the human-recognizable version for the dependency
     */
    private String version;

    /**
     * A descriptor for the type of dependency based on which analyzer added it
     * or collected evidence about it
     */
    private String ecosystem;

    /**
     * Constructs a new Dependency object.
     */
    public Dependency() {
        //empty constructor
    }

    /**
     * Constructs a new Dependency object.
     *
     * @param file the File to create the dependency object from.
     */
    public Dependency(File file) {
        this(file, false);
    }

    /**
     * Constructs a new Dependency object.
     *
     * @param file the File to create the dependency object from.
     * @param isVirtual specifies if the dependency is virtual indicating the
     * file doesn't actually exist.
     */
    public Dependency(File file, boolean isVirtual) {
        this();
        this.isVirtual = isVirtual;
        this.actualFilePath = file.getAbsolutePath();
        this.filePath = this.actualFilePath;
        this.fileName = file.getName();
        this.packagePath = filePath;
        if (!isVirtual && file.isFile()) {
            calculateChecksums(file);
        }
    }

    /**
     * Calculates the checksums for the given file.
     *
     * @param file the file used to calculate the checksums
     */
    private void calculateChecksums(File file) {
        try {
            this.md5sum = Checksum.getMD5Checksum(file);
            this.sha1sum = Checksum.getSHA1Checksum(file);
            this.sha256sum = Checksum.getSHA256Checksum(file);
        } catch (NoSuchAlgorithmException | IOException ex) {
            LOGGER.debug(String.format("Unable to calculate checksums on %s", file), ex);
        }
    }

    /**
     * Constructs a new Dependency object.
     *
     * @param isVirtual specifies if the dependency is virtual indicating the
     * file doesn't actually exist.
     */
    public Dependency(boolean isVirtual) {
        this();
        this.isVirtual = isVirtual;
    }

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
     * Returns the file name of the dependency.
     *
     * @return the file name of the dependency
     */
    public String getFileName() {
        return this.fileName;
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
     * Gets the file path of the dependency.
     *
     * @return the file path of the dependency
     */
    public String getActualFilePath() {
        return this.actualFilePath;
    }

    /**
     * Sets the actual file path of the dependency on disk.
     *
     * @param actualFilePath the file path of the dependency
     */
    public void setActualFilePath(String actualFilePath) {
        this.actualFilePath = actualFilePath;
        this.sha1sum = null;
        this.sha256sum = null;
        this.md5sum = null;
        final File file = getActualFile();
        if (file.isFile()) {
            calculateChecksums(this.getActualFile());
        }
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
     * Returns the file name to display in reports; if no display file name has
     * been set it will default to constructing a name based on the name and
     * version fields, otherwise it will return the actual file name.
     *
     * @return the file name to display
     */
    public String getDisplayFileName() {
        if (displayName != null) {
            return displayName;
        }
        if (name == null) {
            return fileName;
        }
        if (version == null) {
            return name;
        }
        return name + ":" + version;
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
     * Sets the file path of the dependency.
     *
     * @param filePath the file path of the dependency
     */
    public void setFilePath(String filePath) {
//        if (this.packagePath == null || this.packagePath.equals(this.filePath)) {
//            this.packagePath = filePath;
//        }
        this.filePath = filePath;
    }

    /**
     * Returns the MD5 Checksum of the dependency file.
     *
     * @return the MD5 Checksum
     */
    public String getMd5sum() {
        if (md5sum == null) {
            this.md5sum = determineHashes(MD5_HASHING_FUNCTION);
        }

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
        if (sha1sum == null) {
            this.sha1sum = determineHashes(SHA1_HASHING_FUNCTION);
        }
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
     * Returns the SHA256 Checksum of the dependency.
     *
     * @return the SHA256 Checksum of the dependency
     */
    public String getSha256sum() {
        if (sha256sum == null) {
            this.sha256sum = determineHashes(SHA256_HASHING_FUNCTION);
        }
        return sha256sum;
    }

    public void setSha256sum(String sha256sum) {
        this.sha256sum = sha256sum;
    }

    /**
     * Returns an unmodifiable List of Identifiers.
     *
     * @return an unmodifiable List of Identifiers
     */
    public synchronized Set<Identifier> getIdentifiers() {
        return Collections.unmodifiableSet(new HashSet<>(identifiers));
    }

    /**
     * Adds a set of Identifiers to the current list of identifiers. Only used
     * for testing.
     *
     * @param identifiers A set of Identifiers
     */
    protected synchronized void addIdentifiers(Set<Identifier> identifiers) {
        this.identifiers.addAll(identifiers);
    }

    /**
     * Adds an entry to the list of detected Identifiers for the dependency
     * file.
     *
     * @param type the type of identifier (such as CPE)
     * @param value the value of the identifier
     * @param url the URL of the identifier
     */
    public synchronized void addIdentifier(String type, String value, String url) {
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
    public synchronized void addIdentifier(String type, String value, String url, Confidence confidence) {
        final Identifier i = new Identifier(type, value, url);
        i.setConfidence(confidence);
        this.identifiers.add(i);
    }

    /**
     * Removes an identifier from the list of identifiers.
     *
     * @param i the identifier to remove
     */
    public synchronized void removeIdentifier(Identifier i) {
        this.identifiers.remove(i);
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
            this.addEvidence(EvidenceType.VENDOR, source, "groupid", mavenArtifact.getGroupId(), confidence);
        }
        if (mavenArtifact.getArtifactId() != null && !mavenArtifact.getArtifactId().isEmpty()) {
            this.addEvidence(EvidenceType.PRODUCT, source, "artifactid", mavenArtifact.getArtifactId(), confidence);
        }
        if (mavenArtifact.getVersion() != null && !mavenArtifact.getVersion().isEmpty()) {
            this.addEvidence(EvidenceType.VERSION, source, "version", mavenArtifact.getVersion(), confidence);
        }
        boolean found = false;
        if (mavenArtifact.getArtifactUrl() != null && !mavenArtifact.getArtifactUrl().isEmpty()) {
            synchronized (this) {
                for (Identifier i : this.identifiers) {
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
            }
        }
        if (!found && mavenArtifact.getGroupId() != null && mavenArtifact.getArtifactId() != null && mavenArtifact.getVersion() != null) {
            LOGGER.debug("Adding new maven identifier {}", mavenArtifact);
            this.addIdentifier("maven", mavenArtifact.toString(), mavenArtifact.getArtifactUrl(), Confidence.HIGHEST);
        }
    }

    /**
     * Adds an entry to the list of detected Identifiers for the dependency
     * file.
     *
     * @param identifier the identifier to add
     */
    public synchronized void addIdentifier(Identifier identifier) {
        this.identifiers.add(identifier);
    }

    /**
     * Get the unmodifiable set of suppressedIdentifiers.
     *
     * @return the value of suppressedIdentifiers
     */
    public synchronized Set<Identifier> getSuppressedIdentifiers() {
        return Collections.unmodifiableSet(new HashSet<>(suppressedIdentifiers));
    }

    /**
     * Adds an identifier to the list of suppressed identifiers.
     *
     * @param identifier an identifier that was suppressed.
     */
    public synchronized void addSuppressedIdentifier(Identifier identifier) {
        this.suppressedIdentifiers.add(identifier);
    }

    /**
     * Get the unmodifiable sorted set of vulnerabilities.
     *
     * @return the unmodifiable sorted set of vulnerabilities
     */
    public synchronized Set<Vulnerability> getVulnerabilities() {
        return getVulnerabilities(false);
    }

    /**
     * Get the unmodifiable list of vulnerabilities; optionally sorted.
     *
     * @param sorted if true the list will be sorted
     * @return the unmodifiable list set of vulnerabilities
     */
    public synchronized Set<Vulnerability> getVulnerabilities(boolean sorted) {
        final Set<Vulnerability> vulnerabilitySet;
        if (sorted) {
            vulnerabilitySet = new TreeSet<>(vulnerabilities);
        } else {
            vulnerabilitySet = vulnerabilities;
        }
        return Collections.unmodifiableSet(vulnerabilitySet);
    }

    /**
     * Get an unmodifiable set of suppressedVulnerabilities.
     *
     * @return the unmodifiable sorted set of suppressedVulnerabilities
     */
    public synchronized Set<Vulnerability> getSuppressedVulnerabilities() {
        return getSuppressedVulnerabilities(false);
    }

    /**
     * Get an unmodifiable, optionally sorted. set of suppressedVulnerabilities.
     *
     * @param sorted whether or not the set is sorted
     * @return the unmodifiable sorted set of suppressedVulnerabilities
     */
    public synchronized Set<Vulnerability> getSuppressedVulnerabilities(boolean sorted) {
        final Set<Vulnerability> vulnerabilitySet;
        if (sorted) {
            vulnerabilitySet = new TreeSet<>(suppressedVulnerabilities);
        } else {
            vulnerabilitySet = suppressedVulnerabilities;
        }
        return Collections.unmodifiableSet(vulnerabilitySet);
    }

    /**
     * Adds a vulnerability to the set of suppressed vulnerabilities.
     *
     * @param vulnerability the vulnerability that was suppressed
     */
    public synchronized void addSuppressedVulnerability(Vulnerability vulnerability) {
        this.suppressedVulnerabilities.add(vulnerability);
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
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Determines the SHA1 and MD5 sum for the given file.
     *
     * @param hashFunction the hashing function
     * @return the checksum
     */
    private String determineHashes(HashingFunction hashFunction) {
        if (isVirtual) {
            return null;
        }
        try {
            final File file = getActualFile();
            return hashFunction.hash(file);
        } catch (IOException | RuntimeException ex) {
            LOGGER.warn("Unable to read '{}' to determine hashes.", actualFilePath);
            LOGGER.debug("", ex);
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.warn("Unable to use MD5 or SHA1 checksums.");
            LOGGER.debug("", ex);
        }
        return null;
    }

    /**
     * Adds a vulnerability to the dependency.
     *
     * @param vulnerability a vulnerability
     */
    public synchronized void addVulnerability(Vulnerability vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }

    /**
     * Adds a list of vulnerabilities to the dependency.
     *
     * @param vulnerabilities a list of vulnerabilities
     */
    public synchronized void addVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities.addAll(vulnerabilities);
    }

    /**
     * Removes the given vulnerability from the list.
     *
     * @param v the vulnerability to remove
     */
    public synchronized void removeVulnerability(Vulnerability v) {
        this.vulnerabilities.remove(v);
    }

    /**
     * Get the unmodifiable set of {@link #relatedDependencies}. This field is
     * used to collect other dependencies which really represent the same
     * dependency, and may be presented as one item in reports.
     *
     * @return the unmodifiable set of relatedDependencies
     */
    public synchronized Set<Dependency> getRelatedDependencies() {
        return Collections.unmodifiableSet(new HashSet<>(relatedDependencies));
    }

    /**
     * Get the unmodifiable set of projectReferences.
     *
     * @return the unmodifiable set of projectReferences
     */
    public synchronized Set<String> getProjectReferences() {
        return Collections.unmodifiableSet(new HashSet<>(projectReferences));
    }

    /**
     * Adds a project reference.
     *
     * @param projectReference a project reference
     */
    public synchronized void addProjectReference(String projectReference) {
        this.projectReferences.add(projectReference);
    }

    /**
     * Add a collection of project reference.
     *
     * @param projectReferences a set of project references
     */
    public synchronized void addAllProjectReferences(Set<String> projectReferences) {
        this.projectReferences.addAll(projectReferences);
    }

    /**
     * Adds a related dependency.
     *
     * @param dependency a reference to the related dependency
     */
    public synchronized void addRelatedDependency(Dependency dependency) {
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
     * Removes a related dependency.
     *
     * @param dependency the dependency to remove
     */
    public synchronized void removeRelatedDependencies(Dependency dependency) {
        this.relatedDependencies.remove(dependency);
    }

    /**
     * Get the value of availableVersions.
     *
     * @return the value of availableVersions
     */
    public synchronized List<String> getAvailableVersions() {
        return Collections.unmodifiableList(new ArrayList<>(availableVersions));
    }

    /**
     * Adds a version to the available version list.
     *
     * @param version the version to add to the list
     */
    public synchronized void addAvailableVersion(String version) {
        this.availableVersions.add(version);
    }

    /**
     * Returns whether or not this dependency is virtual or not. Virtual
     * dependencies are specified during object constructor. No setter.
     *
     * @return true if Dependency is virtual, false if not
     */
    public boolean isVirtual() {
        return isVirtual;
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
                .append(this.sha256sum, other.sha256sum)
                .append(this.identifiers, other.identifiers)
                .append(this.description, other.description)
                .append(this.license, other.license)
                .append(this.vulnerabilities, other.vulnerabilities)
                .append(this.projectReferences, other.projectReferences)
                .append(this.availableVersions, other.availableVersions)
                .append(this.version, other.version)
                .append(this.ecosystem, other.ecosystem)
                .isEquals();
    }

    /**
     * Generates the HashCode.
     *
     * @return the HashCode
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(3, 47)
                .appendSuper(super.hashCode())
                .append(actualFilePath)
                .append(filePath)
                .append(fileName)
                .append(packagePath)
                .append(md5sum)
                .append(sha1sum)
                .append(sha256sum)
                .append(identifiers)
                .append(description)
                .append(license)
                .append(vulnerabilities)
                .append(projectReferences)
                .append(availableVersions)
                .append(version)
                .append(ecosystem)
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

    /**
     * Add a list of suppressed vulnerabilities to the collection.
     *
     * @param vulns the list of suppressed vulnerabilities to add
     */
    public synchronized void addSuppressedVulnerabilities(List<Vulnerability> vulns) {
        this.suppressedVulnerabilities.addAll(vulns);
    }

    /**
     * @return the version
     */
    public String getVersion() {
        return version;
    }

    /**
     * @param version the version to set
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * @return the ecosystem
     */
    public String getEcosystem() {
        return ecosystem;
    }

    /**
     * @param ecosystem the ecosystem to set
     */
    public void setEcosystem(String ecosystem) {
        this.ecosystem = ecosystem;
    }

    /**
     * A hashing function shortcut.
     */
    interface HashingFunction {

        /**
         * Calculates the checksum for the given file.
         *
         * @param file the source for the checksum
         * @return the string representation of the checksum
         * @throws IOException thrown if there is an I/O error
         * @throws NoSuchAlgorithmException thrown if the algorithm is not found
         */
        String hash(File file) throws IOException, NoSuchAlgorithmException;
    }

}
