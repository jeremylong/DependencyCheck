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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import javax.annotation.concurrent.ThreadSafe;

/**
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class UrlStringUtils {

    /**
     * A regular expression to test if a string contains a URL.
     */
    private static final Pattern CONTAINS_URL_TEST = Pattern.compile("^.*(ht|f)tps?://.*$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
    /**
     * A regular expression to test if a string is a URL.
     */
    private static final Pattern IS_URL_TEST = Pattern.compile("^(ht|f)tps?://.*", Pattern.CASE_INSENSITIVE);
    /**
     * A listing of domain parts that should not be used as evidence. Yes, this
     * is an incomplete list.
     */
    private static final String[] IGNORE_LIST = {"www", "com", "org", "gov", "info", "name", "net", "pro", "tel", "mobi", "xxx", "github", "gitlab"};

    static {
        Arrays.sort(IGNORE_LIST);
    }

    /**
     * Private constructor for a utility class.
     */
    private UrlStringUtils() {
    }

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
     * <p>
     * Takes a URL, in String format, and adds the important parts of the URL to
     * a list of strings.</p>
     * <p>
     * Example, given the following input:</p>
     * <code>"https://www.somedomain.com/path1/path2/file.php?id=439"</code>
     * <p>
     * The function would return:</p>
     * <code>{"some.domain", "path1", "path2", "file"}</code>
     *
     * @param text a URL
     * @return importantParts a list of the important parts of the URL
     * @throws MalformedURLException thrown if the URL is malformed
     */
    @SuppressWarnings("StringSplitter")
    public static List<String> extractImportantUrlData(String text) throws MalformedURLException {
        final List<String> importantParts = new ArrayList<>();
        final URL url = new URL(text);
        final String[] domain = url.getHost().split("\\.");
        //add the domain except www and the tld.
        for (int i = 0; i < domain.length - 1; i++) {
            final String sub = domain[i];
            if (Arrays.binarySearch(IGNORE_LIST, sub.toLowerCase()) < 0) {
                importantParts.add(sub);
            }
        }
        final String document = url.getPath();
        final String[] pathParts = document.split("[\\\\//]");
        for (int i = 0; i < pathParts.length - 1; i++) {
            if (!pathParts[i].isEmpty()) {
                importantParts.add(pathParts[i]);
            }
        }
        if (pathParts.length > 0 && !pathParts[pathParts.length - 1].isEmpty()) {
            final String tmp = pathParts[pathParts.length - 1];
            final int pos = tmp.lastIndexOf('.');
            if (pos > 1) {
                importantParts.add(tmp.substring(0, pos));
            } else if (pos == 0 && tmp.length() > 1) {
                importantParts.add(tmp.substring(1));
            } else {
                importantParts.add(tmp);
            }
        }
        return importantParts;
    }
}
