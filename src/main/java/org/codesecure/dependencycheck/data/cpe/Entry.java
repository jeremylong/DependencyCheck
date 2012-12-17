package org.codesecure.dependencycheck.data.cpe;
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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.document.Document;

/**
 * A single CPE entry from the cpe.xml downloaded from <a
 * href="http://nvd.nist.gov/cpe.cfm">http://nvd.nist.gov/cpe.cfm</a>.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Entry {

    /**
     * This parse method does not fully convert a Lucene Document into a CPE
     * Entry; it only sets the Entry.Name.
     *
     * @param doc a Lucene Document.
     * @return a CPE Entry.
     */
    public static Entry parse(Document doc) {
        Entry entry = new Entry();
        try {
            entry.parseName(doc.get(Fields.NAME));
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Entry.class.getName()).log(Level.SEVERE, null, ex);
            entry.name = doc.get(Fields.NAME);
        }
        return entry;
    }
    /**
     * The title of the CPE
     */
    protected String title;

    /**
     * Get the value of title
     *
     * @return the value of title
     */
    public String getTitle() {
        return title;
    }

    /**
     * Set the value of title
     *
     * @param title new value of title
     */
    public void setTitle(String title) {
        this.title = title;
    }
    /**
     * The name of the CPE entry.
     */
    protected String name;

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
     * The status of the CPE Entry.
     */
    protected String status;

    /**
     * Get the value of status
     *
     * @return the value of status
     */
    public String getStatus() {
        return status;
    }

    /**
     * Set the value of status
     *
     * @param status new value of status
     */
    public void setStatus(String status) {
        this.status = status;
    }
    /**
     * The modification date of the CPE Entry.
     */
    protected Date modificationDate;

    /**
     * Get the value of modificationDate
     *
     * @return the value of modificationDate
     */
    public Date getModificationDate() {
        return modificationDate;
    }

    /**
     * Set the value of modificationDate
     *
     * @param modificationDate new value of modificationDate
     */
    public void setModificationDate(Date modificationDate) {
        this.modificationDate = modificationDate;
    }

    /**
     * Set the value of modificationDate
     *
     * Expected format: yyyy-MM-dd'T'HH:mm:ss.SSS'Z'
     *
     * @param modificationDate new value of modificationDate
     * @throws ParseException is thrown when a parse exception occurs.
     */
    public void setModificationDate(String modificationDate) throws ParseException {

        String formatStr = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
        Date tempDate = null;
        SimpleDateFormat sdf = new SimpleDateFormat(formatStr);
        sdf.setLenient(true);
        tempDate = sdf.parse(modificationDate);

        this.modificationDate = tempDate;
    }
    /**
     * The nvdId.
     */
    protected String nvdId;

    /**
     * Get the value of nvdId
     *
     * @return the value of nvdId
     */
    public String getNvdId() {
        return nvdId;
    }

    /**
     * Set the value of nvdId
     *
     * @param nvdId new value of nvdId
     */
    public void setNvdId(String nvdId) {
        this.nvdId = nvdId;
    }
    /**
     * The vendor name.
     */
    protected String vendor;

    /**
     * Get the value of vendor
     *
     * @return the value of vendor
     */
    public String getVendor() {
        return vendor;
    }

    /**
     * Set the value of vendor
     *
     * @param vendor new value of vendor
     */
    public void setVendor(String vendor) {
        this.vendor = vendor;
    }
    /**
     * The product name.
     */
    protected String product;

    /**
     * Get the value of product
     *
     * @return the value of product
     */
    public String getProduct() {
        return product;
    }

    /**
     * Set the value of product
     *
     * @param product new value of product
     */
    public void setProduct(String product) {
        this.product = product;
    }
    /**
     * The product version.
     */
    protected String version;

    /**
     * Get the value of version
     *
     * @return the value of version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Set the value of version
     *
     * @param version new value of version
     */
    public void setVersion(String version) {
        this.version = version;
    }
    /**
     * The product revision.
     */
    protected String revision;

    /**
     * Get the value of revision
     *
     * @return the value of revision
     */
    public String getRevision() {
        return revision;
    }

    /**
     * Set the value of revision
     *
     * @param revision new value of revision
     */
    public void setRevision(String revision) {
        this.revision = revision;
    }
    /**
     * The search score.
     */
    protected float searchScore;

    /**
     * Get the value of searchScore
     *
     * @return the value of searchScore
     */
    public float getSearchScore() {
        return searchScore;
    }

    /**
     * Set the value of searchScore
     *
     * @param searchScore new value of searchScore
     */
    public void setSearchScore(float searchScore) {
        this.searchScore = searchScore;
    }

    /**
     * <p>Parses a name attribute value, from the cpe.xml, into its
     * corresponding parts: vendor, product, version, revision.</p>
     * <p>Example:</p>
     * <code>&nbsp;&nbsp;&nbsp;cpe:/a:apache:struts:1.1:rc2</code>
     *
     * <p>Results in:</p> <ul> <li>Vendor: apache</li> <li>Product: struts</li>
     * <li>Version: 1.1</li> <li>Revision: rc2</li> </ul>
     *
     * @param cpeName the cpe name
     * @throws UnsupportedEncodingException should never be thrown...
     */
    public void parseName(String cpeName) throws UnsupportedEncodingException {
        this.name = cpeName;
        if (cpeName != null && cpeName.length() > 7) {
            String[] data = cpeName.substring(7).split(":");
            if (data.length >= 1) {
                vendor = URLDecoder.decode(data[0], "UTF-8").replaceAll("[_-]", " ");
                if (data.length >= 2) {
                    product = URLDecoder.decode(data[1], "UTF-8").replaceAll("[_-]", " ");
                    if (data.length >= 3) {
                        version = URLDecoder.decode(data[2], "UTF-8");
                        if (data.length >= 4) {
                            revision = URLDecoder.decode(data[3], "UTF-8");
                        }
                        //ignore edition and language fields.. don't really see them used in the a:
                    }
                }
            }
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Entry other = (Entry) obj;
        if ((this.name == null) ? (other.name != null) : !this.name.equals(other.name)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 83 * hash + (this.name != null ? this.name.hashCode() : 0);
        return hash;
    }
}
