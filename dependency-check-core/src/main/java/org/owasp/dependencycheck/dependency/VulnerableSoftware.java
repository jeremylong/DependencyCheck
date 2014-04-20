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

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.cpe.IndexEntry;

/**
 * A record containing information about vulnerable software. This is referenced from a vulnerability.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class VulnerableSoftware extends IndexEntry implements Serializable, Comparable<VulnerableSoftware> {
    
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(VulnerableSoftware.class.getName());
    /**
     * The serial version UID.
     */
    private static final long serialVersionUID = 307319490326651052L;

    /**
     * Parse a CPE entry from the cpe string representation.
     *
     * @param cpe a cpe entry (e.g. cpe:/a:vendor:software:version)
     */
    public void setCpe(String cpe) {
        try {
            parseName(cpe);
        } catch (UnsupportedEncodingException ex) {
            final String msg = String.format("Character encoding is unsupported for CPE '%s'.", cpe);
            LOGGER.log(Level.WARNING, msg);
            LOGGER.log(Level.FINE, null, ex);
            setName(cpe);
        }
    }

    /**
     * <p>
     * Parses a name attribute value, from the cpe.xml, into its corresponding parts: vendor, product, version,
     * revision.</p>
     * <p>
     * Example:</p>
     * <code>&nbsp;&nbsp;&nbsp;cpe:/a:apache:struts:1.1:rc2</code>
     *
     * <p>
     * Results in:</p> <ul> <li>Vendor: apache</li> <li>Product: struts</li>
     * <li>Version: 1.1</li> <li>Revision: rc2</li> </ul>
     *
     * @param cpeName the cpe name
     * @throws UnsupportedEncodingException should never be thrown...
     */
    @Override
    public void parseName(String cpeName) throws UnsupportedEncodingException {
        this.name = cpeName;
        if (cpeName != null && cpeName.length() > 7) {
            final String[] data = cpeName.substring(7).split(":");
            if (data.length >= 1) {
                this.setVendor(URLDecoder.decode(data[0].replace("+", "%2B"), "UTF-8"));
            }
            if (data.length >= 2) {
                this.setProduct(URLDecoder.decode(data[1].replace("+", "%2B"), "UTF-8"));
            }
            if (data.length >= 3) {
                version = URLDecoder.decode(data[2].replace("+", "%2B"), "UTF-8");
            }
            if (data.length >= 4) {
                revision = URLDecoder.decode(data[3].replace("+", "%2B"), "UTF-8");
            }
            if (data.length >= 5) {
                edition = URLDecoder.decode(data[4].replace("+", "%2B"), "UTF-8");
            }
        }
    }
    /**
     * If present, indicates that previous version are vulnerable.
     */
    private String previousVersion;

    /**
     * Indicates if previous versions of this software are vulnerable.
     *
     * @return if previous versions of this software are vulnerable
     */
    public boolean hasPreviousVersion() {
        return previousVersion != null;
    }

    /**
     * Get the value of previousVersion.
     *
     * @return the value of previousVersion
     */
    public String getPreviousVersion() {
        return previousVersion;
    }

    /**
     * Set the value of previousVersion.
     *
     * @param previousVersion new value of previousVersion
     */
    public void setPreviousVersion(String previousVersion) {
        this.previousVersion = previousVersion;
    }

    /**
     * Standard equals implementation to compare this VulnerableSoftware to another object.
     *
     * @param obj the object to compare
     * @return whether or not the objects are equal
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final VulnerableSoftware other = (VulnerableSoftware) obj;
        if ((this.getName() == null) ? (other.getName() != null) : !this.getName().equals(other.getName())) {
            return false;
        }
        return true;
    }

    /**
     * Standard implementation of hashCode.
     *
     * @return the hashCode for the object
     */
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 83 * hash + (this.getName() != null ? this.getName().hashCode() : 0);
        return hash;
    }

    /**
     * Standard toString() implementation display the name and whether or not previous versions are also affected.
     *
     * @return a string representation of the object
     */
    @Override
    public String toString() {
        return "VulnerableSoftware{ name=" + name + ", previousVersion=" + previousVersion + '}';
    }

    /**
     * Implementation of the comparable interface.
     *
     * @param vs the VulnerableSoftware to compare
     * @return an integer indicating the ordering of the two objects
     */
    @Override
    public int compareTo(VulnerableSoftware vs) {
        int result = 0;
        final String[] left = this.getName().split(":");
        final String[] right = vs.getName().split(":");
        final int max = (left.length <= right.length) ? left.length : right.length;
        if (max > 0) {
            for (int i = 0; result == 0 && i < max; i++) {
                final String[] subLeft = left[i].split("\\.");
                final String[] subRight = right[i].split("\\.");
                final int subMax = (subLeft.length <= subRight.length) ? subLeft.length : subRight.length;
                if (subMax > 0) {
                    for (int x = 0; result == 0 && x < subMax; x++) {
                        if (isPositiveInteger(subLeft[x]) && isPositiveInteger(subRight[x])) {
                            try {
                                result = Long.valueOf(subLeft[x]).compareTo(Long.valueOf(subRight[x]));
//                                final long iLeft = Long.parseLong(subLeft[x]);
//                                final long iRight = Long.parseLong(subRight[x]);
//                                if (iLeft != iRight) {
//                                    if (iLeft > iRight) {
//                                        result = 2;
//                                    } else {
//                                        result = -2;
//                                    }
//                                }
                            } catch (NumberFormatException ex) {
                                //ignore the exception - they obviously aren't numbers
                                if (!subLeft[x].equalsIgnoreCase(subRight[x])) {
                                    result = subLeft[x].compareToIgnoreCase(subRight[x]);
                                }
                            }
                        } else {
                            result = subLeft[x].compareToIgnoreCase(subRight[x]);
                        }
                    }
                    if (result == 0) {
                        if (subLeft.length > subRight.length) {
                            result = 2;
                        }
                        if (subRight.length > subLeft.length) {
                            result = -2;
                        }
                    }
                } else {
                    result = left[i].compareToIgnoreCase(right[i]);
                }
            }
            if (result == 0) {
                if (left.length > right.length) {
                    result = 2;
                }
                if (right.length > left.length) {
                    result = -2;
                }
            }
        } else {
            result = this.getName().compareToIgnoreCase(vs.getName());
        }
        return result;
    }

    /**
     * Determines if the string passed in is a positive integer.
     *
     * @param str the string to test
     * @return true if the string only contains 0-9, otherwise false.
     */
    private static boolean isPositiveInteger(final String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        for (int i = 0; i < str.length(); i++) {
            final char c = str.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }
    /**
     * The name of the cpe.
     */
    private String name;

    /**
     * Get the value of name.
     *
     * @return the value of name
     */
    public String getName() {
        return name;
    }

    /**
     * Set the value of name.
     *
     * @param name new value of name
     */
    public void setName(String name) {
        this.name = name;
    }
    /**
     * The product version number.
     */
    private String version;

    /**
     * Get the value of version.
     *
     * @return the value of version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Set the value of version.
     *
     * @param version new value of version
     */
    public void setVersion(String version) {
        this.version = version;
    }
    /**
     * The product revision version.
     */
    private String revision;

    /**
     * Get the value of revision.
     *
     * @return the value of revision
     */
    public String getRevision() {
        return revision;
    }

    /**
     * Set the value of revision.
     *
     * @param revision new value of revision
     */
    public void setRevision(String revision) {
        this.revision = revision;
    }
    /**
     * The product edition.
     */
    private String edition;

    /**
     * Get the value of edition.
     *
     * @return the value of edition
     */
    public String getEdition() {
        return edition;
    }

    /**
     * Set the value of edition.
     *
     * @param edition new value of edition
     */
    public void setEdition(String edition) {
        this.edition = edition;
    }
}
