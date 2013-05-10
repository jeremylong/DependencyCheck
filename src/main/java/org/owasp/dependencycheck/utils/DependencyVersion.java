/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
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
 * separated by periods. If a different seperator is used the parser will likely
 * fail.</p>
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class DependencyVersion implements Iterable {

    /**
     * Constructor for a empty DependencyVersion.
     */
    public DependencyVersion() {
        versionParts = new ArrayList<String>();
    }

    /**
     * Constructor for a DependencyVersion that will parse a version string.
     * @param version the version number to parse
     */
    public DependencyVersion(String version) {
        parseVersion(version);
    }

    /**
     * Parses a version string into its sub parts: major, minor, revision, build, etc.
     * @param version the version string to parse
     */
    public final void parseVersion(String version) {
        versionParts = new ArrayList<String>();
        if (version != null) {
            final Pattern rx = Pattern.compile("(\\d+|[a-z]+\\d+)");
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
     * @return a string representing the version.
     */
    @Override
    public String toString() {
        return StringUtils.join(versionParts.toArray(), ".");
    }
}
