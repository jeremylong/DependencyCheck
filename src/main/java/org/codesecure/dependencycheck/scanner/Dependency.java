package org.codesecure.dependencycheck.scanner;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.util.ArrayList;
import java.util.List;

/**
 * A program dependency. This object is one of the core components within
 * DependencyCheck. It is used to collect information about the dependency
 * in the form of evidence. The Evidence is then used to determine if there
 * are any known, published, vulnerabilities associated with the program
 * dependency.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Dependency {

    /**
     * The file path of the dependency.
     */
    private String filePath = null;
    /**
     * The file name of the dependency.
     */
    private String fileName = null;
    /**
     * The md5 hash of the dependency.
     */
    private String md5sum = null;
    /**
     * The SHA1 hash of the dependency.
     */
    private String sha1sum = null;
    /**
     * A list of CPEs.
     */
    private List<String> cpes = null;
    /**
     * A collection of vendor evidence.
     */
    protected EvidenceCollection vendorEvidence = null;
    /**
     * A collection of title evidence.
     */
    protected EvidenceCollection titleEvidence = null;
    /**
     * A collection of version evidence.
     */
    protected EvidenceCollection versionEvidence = null;

    public Dependency() {
        vendorEvidence = new EvidenceCollection();
        titleEvidence = new EvidenceCollection();
        versionEvidence = new EvidenceCollection();
        cpes = new ArrayList<String>();
    }
    
    /**
     * Returns the file name of the JAR.
     *
     * @return the file name of the JAR
     */
    public String getFileName() {
        return this.fileName;
    }

    /**
     * Sets the file name of the JAR.
     *
     * @param fileName the file name of the JAR
     */
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    /**
     * Sets the file path of the JAR.
     * @param filePath the file path of the JAR
     */
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    /**
     * Gets the file path of the JAR.
     * @return the file path of the JAR.
     */
    public String getFilePath() {
        return this.filePath;
    }

    /**
     * Returns the MD5 Checksum of the JAR file.
     *
     * @return the MD5 Checksum
     */
    public String getMd5sum() {
        return this.md5sum;
    }

    /**
     * Sets the MD5 Checksum of the JAR.
     *
     * @param md5sum the MD5 Checksum
     */
    public void setMd5sum(String md5sum) {
        this.md5sum = md5sum;
    }

    /**
     * Returns the SHA1 Checksum of the JAR.
     *
     * @return the SHA1 Checksum
     */
    public String getSha1sum() {
        return this.sha1sum;
    }

    /**
     * Sets the SHA1 Checksum of the JAR.
     *
     * @param sha1sum the SHA1 Checksum
     */
    public void setSha1sum(String sha1sum) {
        this.sha1sum = sha1sum;
    }

    /**
     * Returns a List of possible CPE keys.
     *
     * @return an ArrayList containing possible CPE keys.
     */
    public List<String> getCPEs() {
        return this.cpes;
    }

    /**
     * Sets a List of possible CPE keys.
     *
     * @param cpe A list of CPE values.
     */
    public void setCPEs(List<String> cpe) {
        this.cpes = cpe;
    }

    /**
     * Adds an entry to the list of detected CPE keys for the dependency file.
     *
     * @param cpe a CPE key for the dependency file
     */
    public void addCPEentry(String cpe) {
        if (cpes == null) {
            cpes = new ArrayList<String>();
        }
        this.cpes.add(cpe);
    }

    /**
     * Returns the evidence used to identify this dependency.
     *
     * @return an EvidenceCollection.
     */
    public EvidenceCollection getEvidence() {
        return EvidenceCollection.mergeUsed(this.titleEvidence, this.vendorEvidence, this.versionEvidence);
    }
    
    
    /**
     * Returns the evidence used to identify this dependency.
     *
     * @return an EvidenceCollection.
     */
    public EvidenceCollection getEvidenceUsed() {
        EvidenceCollection ec = EvidenceCollection.mergeUsed(this.titleEvidence, this.vendorEvidence, this.versionEvidence);
        return ec;
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
     * Gets the Title Evidence.
     *
     * @return an EvidenceCollection.
     */
    public EvidenceCollection getTitleEvidence() {
        return this.titleEvidence;
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
     * Determines if the specified string was used when searching.
     *
     * @param str is the string that is being checked if it was used.
     * @return true or false.
     */
    public boolean containsUsedString(String str) {
        if (str == null) {
            return false;
        }

        String fnd = str.toLowerCase();

        //TODO add the filename is analyzed and added as evidence
        //TODO remove special characters from filename and check this (including spaces)
        if (this.fileName != null && this.fileName.contains(fnd)) {
            return true;
        }

        if (vendorEvidence.containsUsedString(str)) {
            return true;
        }
        if (titleEvidence.containsUsedString(str)) {
            return true;
        }
        if (versionEvidence.containsUsedString(fnd)) {
            return true;
        }

        return false;
    }
}
