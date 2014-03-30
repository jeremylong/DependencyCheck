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
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.FileUtils;

/**
 * A program dependency. This object is one of the core components within DependencyCheck. It is used to collect
 * information about the dependency in the form of evidence. The Evidence is then used to determine if there are any
 * known, published, vulnerabilities associated with the program dependency.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class Dependency implements Comparable<Dependency> {

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
     * The file extension of the dependency.
     */
    private String fileExtension;
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
     * Constructs a new Dependency object.
     */
    public Dependency() {
        vendorEvidence = new EvidenceCollection();
        productEvidence = new EvidenceCollection();
        versionEvidence = new EvidenceCollection();
        identifiers = new TreeSet<Identifier>();
        vulnerabilities = new TreeSet<Vulnerability>(new VulnerabilityComparator());
        suppressedIdentifiers = new TreeSet<Identifier>();
        suppressedVulnerabilities = new TreeSet<Vulnerability>(new VulnerabilityComparator());
    }

    /**
     * Constructs a new Dependency object.
     *
     * @param file the File to create the dependency object from.
     */
    public Dependency(File file) {
        this();
        this.actualFilePath = file.getPath();
        this.filePath = this.actualFilePath;
        this.fileName = file.getName();
        this.fileExtension = FileUtils.getFileExtension(fileName);
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
     * Returns the file name of the dependency with the backslash escaped for use in JavaScript. This is a complete hack
     * as I could not get the replace to work in the template itself.
     *
     * @return the file name of the dependency with the backslash escaped for use in JavaScript
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
        this.filePath = filePath;
    }

    /**
     * <p>
     * Gets the file path of the dependency.</p>
     * <p>
     * <b>NOTE:</b> This may not be the actual path of the file on disk. The actual path of the file on disk can be
     * obtained via the getActualFilePath().</p>
     *
     * @return the file path of the dependency
     */
    public String getFilePath() {
        return this.filePath;
    }

    /**
     * Sets the file name of the dependency.
     *
     * @param fileExtension the file name of the dependency
     */
    public void setFileExtension(String fileExtension) {
        this.fileExtension = fileExtension;
    }

    /**
     * Gets the file extension of the dependency.
     *
     * @return the file extension of the dependency
     */
    public String getFileExtension() {
        return this.fileExtension;
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
     * Adds an entry to the list of detected Identifiers for the dependency file.
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
     * Adds an entry to the list of detected Identifiers for the dependency file.
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
     * Adds an entry to the list of detected Identifiers for the dependency file.
     *
     * @param identifier the identifier to add
     */
    public void addIdentifier(Identifier identifier) {
        this.identifiers.add(identifier);
    }
    /**
     * A set of identifiers that have been suppressed.
     */
    private Set<Identifier> suppressedIdentifiers;

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
     * A set of vulnerabilities that have been suppressed.
     */
    private SortedSet<Vulnerability> suppressedVulnerabilities;

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
     * The description of the JAR file.
     */
    private String description;

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
     * The license that this dependency uses.
     */
    private String license;

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
     * A list of vulnerabilities for this dependency.
     */
    private SortedSet<Vulnerability> vulnerabilities;

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
            final String msg = String.format("Unable to read '%s' to determine hashes.", file.getName());
            Logger.getLogger(Dependency.class.getName()).log(Level.WARNING, msg);
            Logger.getLogger(Dependency.class.getName()).log(Level.FINE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            final String msg = "Unable to use MD5 of SHA1 checksums.";
            Logger.getLogger(Dependency.class.getName()).log(Level.WARNING, msg);
            Logger.getLogger(Dependency.class.getName()).log(Level.FINE, null, ex);
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
     * A collection of related dependencies.
     */
    private Set<Dependency> relatedDependencies = new TreeSet<Dependency>();

    /**
     * Get the value of relatedDependencies.
     *
     * @return the value of relatedDependencies
     */
    public Set<Dependency> getRelatedDependencies() {
        return relatedDependencies;
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
     * Adds a related dependency.
     *
     * @param dependency a reference to the related dependency
     */
    public void addRelatedDependency(Dependency dependency) {
        relatedDependencies.add(dependency);
    }

    /**
     * Implementation of the Comparable<Dependency> interface. The comparison is solely based on the file name.
     *
     * @param o a dependency to compare
     * @return an integer representing the natural ordering
     */
    public int compareTo(Dependency o) {
        return this.getFileName().compareToIgnoreCase(o.getFileName());
    }

    /**
     * Implementation of the equals method.
     *
     * @param obj the object to compare
     * @return true if the objects are equal, otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Dependency other = (Dependency) obj;
        if ((this.actualFilePath == null) ? (other.actualFilePath != null) : !this.actualFilePath.equals(other.actualFilePath)) {
            return false;
        }
        if ((this.filePath == null) ? (other.filePath != null) : !this.filePath.equals(other.filePath)) {
            return false;
        }
        if ((this.fileName == null) ? (other.fileName != null) : !this.fileName.equals(other.fileName)) {
            return false;
        }
        if ((this.fileExtension == null) ? (other.fileExtension != null) : !this.fileExtension.equals(other.fileExtension)) {
            return false;
        }
        if ((this.md5sum == null) ? (other.md5sum != null) : !this.md5sum.equals(other.md5sum)) {
            return false;
        }
        if ((this.sha1sum == null) ? (other.sha1sum != null) : !this.sha1sum.equals(other.sha1sum)) {
            return false;
        }
        if (this.identifiers != other.identifiers && (this.identifiers == null || !this.identifiers.equals(other.identifiers))) {
            return false;
        }
        if (this.vendorEvidence != other.vendorEvidence && (this.vendorEvidence == null || !this.vendorEvidence.equals(other.vendorEvidence))) {
            return false;
        }
        if (this.productEvidence != other.productEvidence && (this.productEvidence == null || !this.productEvidence.equals(other.productEvidence))) {
            return false;
        }
        if (this.versionEvidence != other.versionEvidence && (this.versionEvidence == null || !this.versionEvidence.equals(other.versionEvidence))) {
            return false;
        }
        if ((this.description == null) ? (other.description != null) : !this.description.equals(other.description)) {
            return false;
        }
        if ((this.license == null) ? (other.license != null) : !this.license.equals(other.license)) {
            return false;
        }
        if (this.vulnerabilities != other.vulnerabilities && (this.vulnerabilities == null || !this.vulnerabilities.equals(other.vulnerabilities))) {
            return false;
        }
        if (this.relatedDependencies != other.relatedDependencies
                && (this.relatedDependencies == null || !this.relatedDependencies.equals(other.relatedDependencies))) {
            return false;
        }
        return true;
    }

    /**
     * Generates the HashCode.
     *
     * @return the HashCode
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 47 * hash + (this.actualFilePath != null ? this.actualFilePath.hashCode() : 0);
        hash = 47 * hash + (this.filePath != null ? this.filePath.hashCode() : 0);
        hash = 47 * hash + (this.fileName != null ? this.fileName.hashCode() : 0);
        hash = 47 * hash + (this.fileExtension != null ? this.fileExtension.hashCode() : 0);
        hash = 47 * hash + (this.md5sum != null ? this.md5sum.hashCode() : 0);
        hash = 47 * hash + (this.sha1sum != null ? this.sha1sum.hashCode() : 0);
        hash = 47 * hash + (this.identifiers != null ? this.identifiers.hashCode() : 0);
        hash = 47 * hash + (this.vendorEvidence != null ? this.vendorEvidence.hashCode() : 0);
        hash = 47 * hash + (this.productEvidence != null ? this.productEvidence.hashCode() : 0);
        hash = 47 * hash + (this.versionEvidence != null ? this.versionEvidence.hashCode() : 0);
        hash = 47 * hash + (this.description != null ? this.description.hashCode() : 0);
        hash = 47 * hash + (this.license != null ? this.license.hashCode() : 0);
        hash = 47 * hash + (this.vulnerabilities != null ? this.vulnerabilities.hashCode() : 0);
        hash = 47 * hash + (this.relatedDependencies != null ? this.relatedDependencies.hashCode() : 0);
        return hash;
    }

    /**
     * Standard toString() implementation showing the filename, actualFilePath, and filePath.
     *
     * @return the string representation of the file
     */
    @Override
    public String toString() {
        return "Dependency{ fileName='" + fileName + "', actualFilePath='" + actualFilePath + "', filePath='" + filePath + "'}";
    }
}
