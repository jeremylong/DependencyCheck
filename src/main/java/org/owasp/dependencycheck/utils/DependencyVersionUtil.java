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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <p>A utility class to extract version numbers from file names (or other strings
 * containing version numbers.</p>
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public final class DependencyVersionUtil {
    /**
     * Regular expression to extract version numbers from file names.
     */
    private static final Pattern RX_VERSION = Pattern.compile("\\d+(\\.\\d+)+(\\.?[a-zA-Z_-]{1,3}\\d+)?");

    /**
     * Private constructor for utility class.
     */
    private DependencyVersionUtil() {
    }

    /**
     * <p>A utility class to extract version numbers from file names (or other strings
     * containing version numbers.<br/>
     * Example:<br/>
     * Give the file name: library-name-1.4.1r2-release.jar<br/>
     * This function would return: 1.4.1.r2</p>
     *
     * @param filename the filename being analyzed
     * @return a DependencyVersion containing the version
     */
    public static DependencyVersion parseVersionFromFileName(String filename) {
        if (filename == null) {
            return null;
        }
        String version = null;
        final Matcher matcher = RX_VERSION.matcher(filename);
        if (matcher.find()) {
            version = matcher.group();
        }
        //throw away the results if there are two things that look like version numbers
        if (matcher.find()) {
            return null;
        }
        if (version == null) {
            return null;
        }
        return new DependencyVersion(version);
    }
}
