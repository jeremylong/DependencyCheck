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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Pattern;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class UrlStringUtils {

    /**
     * Private constructor for a utility class.
     */
    private UrlStringUtils() {
    }
    /**
     * A regular expression to test if a string contains a URL.
     */
    private static final Pattern CONTAINS_URL_TEST = Pattern.compile("^.*(ht|f)tps?://.*$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
    /**
     * A regular expression to test if a string is a URL.
     */
    private static final Pattern IS_URL_TEST = Pattern.compile("^(ht|f)tps?://.*", Pattern.CASE_INSENSITIVE);

    /**
     * Tests if the text provided contains a URL. This is somewhat limited
     * search in that it only looks for (ftp|http|https)://
     *
     * @param text the text to search
     * @return true if the text contains a url, otherwise false
     */
    public static boolean containsUrl(String text) {
        return CONTAINS_URL_TEST.matcher(text).matches();
    }

    /**
     * Tests if the given text is url.
     *
     * @param text the string to test
     * @return returns true if the text is a url, otherwise false
     */
    public static boolean isUrl(String text) {
        return IS_URL_TEST.matcher(text).matches();
    }
    /**
     * A listing of domain parts that should not be used as evidence. Yes, this
     * is an incomplete list.
     */
    private static final HashSet<String> IGNORE_LIST = new HashSet<String>(
            Arrays.asList("www", "com", "org", "gov", "info", "name", "net", "pro", "tel", "mobi", "xxx"));

    /**
     * <p>Takes a URL, in String format, and adds the important parts of the URL
     * to a list of strings.</p>
     * <p>Example, given the following input:</p>
     * <code>"https://www.somedomain.com/path1/path2/file.php?id=439"</code>
     * <p>The function would return:</p>
     * <code>{"some.domain", "path1", "path2", "file"}</code>
     *
     * @param text a URL
     * @return importantParts a list of the important parts of the URL
     * @throws MalformedURLException thrown if the URL is malformed
     */
    public static List<String> extractImportantUrlData(String text) throws MalformedURLException {
        final ArrayList<String> importantParts = new ArrayList<String>();
        final URL url = new URL(text);
        final String[] domain = url.getHost().split("\\.");
        //add the domain except www and the tld.
        for (int i = 0; i < domain.length - 1; i++) {
            final String sub = domain[i];
            if (!IGNORE_LIST.contains(sub.toLowerCase())) {
                importantParts.add(sub);
            }
        }
        final String document = url.getPath();
        final String[] pathParts = document.split("[\\//]");
        for (int i = 0; i < pathParts.length - 2; i++) {
            if (!pathParts[i].isEmpty()) {
                importantParts.add(pathParts[i]);
            }
        }
        if (pathParts.length > 0 && !pathParts[pathParts.length - 1].isEmpty()) {
            final String fileNameNoExt = pathParts[pathParts.length - 1].replaceAll("\\..*{0,5}$", "");
            importantParts.add(fileNameNoExt);
        }
        return importantParts;
    }
}
