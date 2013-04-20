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
package org.owasp.dependencycheck.dependency;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.cpe.Entry;

/**
 * A record containing information about vulnerable software. This
 * is referenced from a vulnerability.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class VulnerableSoftware extends Entry implements Serializable, Comparable<VulnerableSoftware> {

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
            Logger.getLogger(VulnerableSoftware.class.getName()).log(Level.SEVERE, null, ex);
            setName(cpe);
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

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 83 * hash + (this.getName() != null ? this.getName().hashCode() : 0);
        return hash;
    }

    /**
     * Implementation of the comparable interface.
     * @param vs the VulnerableSoftware to compare
     * @return an integer indicating the ordering of the two objects
     */
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
                            final int iLeft = Integer.parseInt(subLeft[x]);
                            final int iRight = Integer.parseInt(subRight[x]);
                            if (iLeft != iRight) {
                                if (iLeft > iRight) {
                                    result = 2;
                                } else {
                                    result = -2;
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
}
