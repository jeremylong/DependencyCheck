/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;

/**
 * <p>Simple object to track the parts of a version number. The parts are
 * contained in a List such that version 1.2.3 will be stored as:
 * <code>versionParts[0] = 1;
 * versionParts[1] = 2;
 * versionParts[2] = 3;
 * </code></p>
 * <p>Note, the parser contained in this class expects the version numbers to be
 * separated by periods. If a different separator is used the parser will likely
 * fail.</p>
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DependencyVersion implements Iterable, Comparable<DependencyVersion> {

    /**
     * Constructor for a empty DependencyVersion.
     */
    public DependencyVersion() {
    }

    /**
     * Constructor for a DependencyVersion that will parse a version string.
     * <b>Note</b>, this should only be used when the version passed in is
     * already known to be a well formated version number. Otherwise,
     * DependencyVersionUtil.parseVersion() should be used instead.
     *
     * @param version the well formated version number to parse
     */
    public DependencyVersion(String version) {
        parseVersion(version);
    }

    /**
     * Parses a version string into its sub parts: major, minor, revision,
     * build, etc. <b>Note</b>, this should only be used to parse something that
     * is already known to be a version number.
     *
     * @param version the version string to parse
     */
    public final void parseVersion(String version) {
        versionParts = new ArrayList<String>();
        if (version != null) {
            final Pattern rx = Pattern.compile("(\\d+|[a-z]+\\d+|(release|beta|alpha)$)");
            final Matcher matcher = rx.matcher(version.toLowerCase());
            while (matcher.find()) {
                versionParts.add(matcher.group());
            }
            if (versionParts.isEmpty()) {
                versionParts.add(version);
            }
        }
    }
    /**
     * A list of the version parts.
     */
    private List<String> versionParts;

    /**
     * Get the value of versionParts.
     *
     * @return the value of versionParts
     */
    public List<String> getVersionParts() {
        return versionParts;
    }

    /**
     * Set the value of versionParts.
     *
     * @param versionParts new value of versionParts
     */
    public void setVersionParts(List<String> versionParts) {
        this.versionParts = versionParts;
    }

    /**
     * Retrieves an iterator for the version parts.
     *
     * @return an iterator for the version parts
     */
    public Iterator iterator() {
        return versionParts.iterator();
    }

    /**
     * Reconstructs the version string from the split version parts.
     *
     * @return a string representing the version.
     */
    @Override
    public String toString() {
        return StringUtils.join(versionParts.toArray(), ".");
    }

    /**
     * Compares the equality of this object to the one passed in as a parameter.
     *
     * @param obj the object to compare equality
     * @return returns true only if the two objects are equal, otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final DependencyVersion other = (DependencyVersion) obj;
        final int max = (this.versionParts.size() < other.versionParts.size())
                ? this.versionParts.size() : other.versionParts.size();
        //TODO steal better version of code from compareTo
        for (int i = 0; i < max; i++) {
            final String thisPart = this.versionParts.get(i);
            final String otherPart = other.versionParts.get(i);
            if (!thisPart.equals(otherPart)) {
                return false;
            }
        }
        if (this.versionParts.size() > max) {
            for (int i = max; i < this.versionParts.size(); i++) {
                if (!"0".equals(this.versionParts.get(i))) {
                    return false;
                }
            }
        }

        if (other.versionParts.size() > max) {
            for (int i = max; i < other.versionParts.size(); i++) {
                if (!"0".equals(other.versionParts.get(i))) {
                    return false;
                }
            }
        }

        /*
         *  if (this.versionParts != other.versionParts && (this.versionParts == null || !this.versionParts.equals(other.versionParts))) {
         *      return false;
         *  }
         */
        return true;
    }

    /**
     * Calculates the hashCode for this object.
     *
     * @return the hashCode
     */
    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + (this.versionParts != null ? this.versionParts.hashCode() : 0);
        return hash;
    }

    /**
     * Determines if the three most major major version parts are identical. For
     * instances, if version 1.2.3.4 was compared to 1.2.3 this function would
     * return true.
     *
     * @param version the version number to compare
     * @return true if the first three major parts of the version are identical
     */
    public boolean matchesAtLeastThreeLevels(DependencyVersion version) {
        if (version == null) {
            return false;
        }

        boolean ret = true;
        int max = (this.versionParts.size() < version.versionParts.size())
                ? this.versionParts.size() : version.versionParts.size();

        if (max > 3) {
            max = 3;
        }

        for (int i = 0; i < max; i++) {
            if (this.versionParts.get(i) == null || !this.versionParts.get(i).equals(version.versionParts.get(i))) {
                ret = false;
                break;
            }
        }

        return ret;
    }

    @Override
    public int compareTo(DependencyVersion version) {
        if (version == null) {
            return 1;
        }
        final List<String> left = this.getVersionParts();
        final List<String> right = version.getVersionParts();
        final int max = left.size() < right.size() ? left.size() : right.size();

        for (int i = 0; i < max; i++) {
            final String lStr = left.get(i);
            final String rStr = right.get(i);
            if (lStr.equals(rStr)) {
                continue;
            }
            try {
                final int l = Integer.parseInt(lStr);
                final int r = Integer.parseInt(rStr);
                if (l < r) {
                    return -1;
                } else if (l > r) {
                    return 1;
                }
            } catch (NumberFormatException ex) {
                final int comp = left.get(i).compareTo(right.get(i));
                if (comp < 0) {
                    return -1;
                } else if (comp > 0) {
                    return 1;
                }
            }
        }
        if (left.size() < right.size()) {
            return -1;
        } else if (left.size() > right.size()) {
            return 1;
        } else {
            return 0;
        }
    }
}
