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
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.data.cpe.IndexEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A record containing information about vulnerable software. This is referenced from a vulnerability.
 *
 * @author Jeremy Long
 */
public class VulnerableSoftware extends IndexEntry implements Serializable, Comparable<VulnerableSoftware> {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(VulnerableSoftware.class);
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
            LOGGER.warn("Character encoding is unsupported for CPE '{}'.", cpe);
            LOGGER.debug("", ex);
            setName(cpe);
        }
    }

    /**
     * <p>
     * Parses a name attribute value, from the cpe.xml, into its corresponding parts: vendor, product, version, update.</p>
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
            final String cpeNameWithoutPrefix = cpeName.substring(7);
            final String[] data = StringUtils.split(cpeNameWithoutPrefix, ':');
            if (data.length >= 1) {
                this.setVendor(urlDecode(data[0]));
            }
            if (data.length >= 2) {
                this.setProduct(urlDecode(data[1]));
            }
            if (data.length >= 3) {
                version = urlDecode(data[2]);
            }
            if (data.length >= 4) {
                update = urlDecode(data[3]);
            }
            if (data.length >= 5) {
                edition = urlDecode(data[4]);
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
        return !((this.name == null) ? (other.getName() != null) : !this.name.equals(other.getName()));
    }

    /**
     * Standard implementation of hashCode.
     *
     * @return the hashCode for the object
     */
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 83 * hash + (this.name != null ? this.name.hashCode() : 0);
        return hash;
    }

    /**
     * Standard toString() implementation display the name and whether or not previous versions are also affected.
     *
     * @return a string representation of the object
     */
    @Override
    public String toString() {
        return "VulnerableSoftware{" + name + "[" + previousVersion + "]}";
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
        final String[] left = StringUtils.split(this.name, ':');
        final String[] right = StringUtils.split(vs.getName(), ':');
        final int max = (left.length <= right.length) ? left.length : right.length;
        if (max > 0) {
            for (int i = 0; result == 0 && i < max; i++) {
                final String[] subLeft = left[i].split("(\\.|-)");
                final String[] subRight = right[i].split("(\\.|-)");
                final int subMax = (subLeft.length <= subRight.length) ? subLeft.length : subRight.length;
                if (subMax > 0) {
                    for (int x = 0; result == 0 && x < subMax; x++) {
                        if (isPositiveInteger(subLeft[x]) && isPositiveInteger(subRight[x])) {
                            try {
                                result = Long.valueOf(subLeft[x]).compareTo(Long.valueOf(subRight[x]));
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
     * To be counted as a positive integer, the string must only contain 0-9
     * and must not have any leading zeros (though "0" is a valid positive
     * integer).
     *
     * @param str the string to test
     * @return true if the string only contains 0-9, otherwise false.
     */
    protected static boolean isPositiveInteger(final String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }

        // numbers with leading zeros should not be treated as numbers
        // (e.g. when comparing "01" <-> "1")
        if (str.charAt(0) == '0' && str.length() > 1) {
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
     * The product update version.
     */
    private String update;

    /**
     * Get the value of update.
     *
     * @return the value of update
     */
    public String getUpdate() {
        return update;
    }

    /**
     * Set the value of update.
     *
     * @param update new value of update
     */
    public void setUpdate(String update) {
        this.update = update;
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

    /**
     * Replaces '+' with '%2B' and then URL Decodes the string attempting first UTF-8, then ASCII, then default.
     *
     * @param string the string to URL Decode
     * @return the URL Decoded string
     */
    private String urlDecode(String string) {
        final String text = string.replace("+", "%2B");
        String result;
        try {
            result = URLDecoder.decode(text, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            try {
                result = URLDecoder.decode(text, "ASCII");
            } catch (UnsupportedEncodingException ex1) {
                result = defaultUrlDecode(text);
            }
        }
        return result;
    }

    /**
     * Call {@link java.net.URLDecoder#decode(String)} to URL decode using the default encoding.
     *
     * @param text www-form-encoded URL to decode
     * @return the newly decoded String
     */
    @SuppressWarnings("deprecation")
    private String defaultUrlDecode(final String text) {
        return URLDecoder.decode(text);
    }
}
