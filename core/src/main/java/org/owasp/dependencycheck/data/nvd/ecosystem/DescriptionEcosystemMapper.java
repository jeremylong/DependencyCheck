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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.ecosystem;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

/**
 * Helper utility for mapping CVEs to their ecosystems based on the description.
 *
 * @author skjolber
 */
public class DescriptionEcosystemMapper {

    // static fields for thread-safe + hardcoded functionality
    /**
     * The array of ecosystems.
     */
    private static final String[] ECOSYSTEMS;
    /**
     * A helper map to retrieve the index of an ecosystem.
     */
    private static final int[] HINT_TO_ECOSYSTEM_LOOKUP;
    /**
     * Map of strings to ecosystems.
     */
    private static final TreeMap<String, EcosystemHint> ECOSYSTEM_MAP; // thread safe for reading

    static {
        ECOSYSTEM_MAP = new TreeMap<>();

        for (FileExtensionHint fileExtensionHint : FileExtensionHint.values()) {
            ECOSYSTEM_MAP.put(fileExtensionHint.getValue(), fileExtensionHint);
        }
        for (DescriptionKeywordHint descriptionKeywordHint : DescriptionKeywordHint.values()) {
            ECOSYSTEM_MAP.put(descriptionKeywordHint.getValue(), descriptionKeywordHint);
        }

        final Map<String, Integer> ecosystemIndexes = new HashMap<>();

        HINT_TO_ECOSYSTEM_LOOKUP = new int[ECOSYSTEM_MAP.size()];

        int index = 0;
        for (Entry<String, EcosystemHint> entry : ECOSYSTEM_MAP.entrySet()) {
            final EcosystemHint ecosystemHint = entry.getValue();

            Integer ecosystemIndex = ecosystemIndexes.get(ecosystemHint.getEcosystem());
            if (ecosystemIndex == null) {
                ecosystemIndex = ecosystemIndexes.size();

                ecosystemIndexes.put(ecosystemHint.getEcosystem(), ecosystemIndex);
            }

            HINT_TO_ECOSYSTEM_LOOKUP[index] = ecosystemIndex;

            index++;
        }

        ECOSYSTEMS = new String[ecosystemIndexes.size()];
        ecosystemIndexes.entrySet().forEach((e) -> {
            ECOSYSTEMS[e.getValue()] = e.getKey();
        });
    }

    // take advantage of chars also being numbers
    /**
     * Prefix prefix for matching ecosystems.
     */
    private final boolean[] keywordPrefixes = getPrefixesFor(" -(\"'");
    /**
     * Postfix prefix for matching ecosystems.
     */
    private final boolean[] keywordPostfixes = getPrefixesFor(" -)\"',.:;");
    /**
     * Aho Corasick double array trie used for parsing and matching ecosystems.
     */
    private final StringAhoCorasickDoubleArrayTrie<EcosystemHint> ahoCorasickDoubleArrayTrie;

    /**
     * Constructs a new description ecosystem mapper.
     */
    public DescriptionEcosystemMapper() {
        ahoCorasickDoubleArrayTrie = toAhoCorasickDoubleArrayTrie();
    }

    protected static boolean[] getPrefixesFor(String str) {
        int max = -1;
        for (int i = 0; i < str.length(); i++) {
            if (max < str.charAt(i)) {
                max = str.charAt(i);
            }
        }

        final boolean[] delimiters = new boolean[max + 1];
        for (int i = 0; i < str.length(); i++) {
            delimiters[str.charAt(i)] = true;
        }
        return delimiters;
    }

    protected static StringAhoCorasickDoubleArrayTrie<EcosystemHint> toAhoCorasickDoubleArrayTrie() {
        final StringAhoCorasickDoubleArrayTrie<EcosystemHint> exact = new StringAhoCorasickDoubleArrayTrie<>();
        exact.build(ECOSYSTEM_MAP);
        return exact;
    }

    protected static boolean isExtension(String str, int begin, int end) {
        if (str.length() != end && Character.isLetterOrDigit(str.charAt(end))) {
            return false;
        }

        return isLowercaseAscii(str, begin + 1, end);
    }

    protected static boolean isLowercaseAscii(String multicase, int start, int end) {
        for (int i = start; i < end; i++) {
            final char c = multicase.charAt(i);

            if (c < 'a' || c > 'z') {
                return false;
            }
        }
        return true;
    }

    /**
     * Tests if the string is a URL by looking for '://'.
     *
     * @param c the text to test.
     * @param begin the position in the string to begin searching; note the
     * search is decreasing to 0
     * @return <code>true</code> if `://` is found; otherwise <code>false</code>
     */
    public static boolean isURL(String c, int begin) {
        int pos = begin - 2;

        while (pos > 2) {
            pos--;

            if (c.charAt(pos) == ' ') {
                return false;
            }
            if (c.charAt(pos) == ':') {
                return c.charAt(pos + 1) == '/' && c.charAt(pos + 2) == '/';
            }
        }

        return false;
    }

    protected void increment(int i, int[] ecosystemMap) {
        ecosystemMap[HINT_TO_ECOSYSTEM_LOOKUP[i]]++;
    }

    /**
     * Returns the ecosystem if identified by English description from the CVE
     * data.
     *
     * @param cve the CVE data
     * @return the ecosystem if identified
     */
    public String getEcosystem(DefCveItem cve) {
        final int[] ecosystemMap = new int[ECOSYSTEMS.length];
        cve.getCve().getDescription().getDescriptionData().stream()
                .filter((langString) -> (langString.getLang().equals("en")))
                .forEachOrdered((langString) -> {
                    search(langString.getValue(), ecosystemMap);
                });
        return getResult(ecosystemMap);
    }

    /**
     * Determines the ecosystem for the given string.
     *
     * @param multicase the string to test
     * @return the ecosystem
     */
    public String getEcosystem(String multicase) {
        final int[] ecosystemMap = new int[ECOSYSTEMS.length];
        search(multicase, ecosystemMap);
        return getResult(ecosystemMap);
    }

    private void search(String multicase, int[] ecosystemMap) {
        final String c = multicase.toLowerCase();
        ahoCorasickDoubleArrayTrie.parseText(c, (begin, end, value, index) -> {
            if (value.getNature() == EcosystemHintNature.FILE_EXTENSION) {
                if (!isExtension(multicase, begin, end)) {
                    return;
                }

                final String ecosystem = value.getEcosystem();
                // real extension, if not part of url
                if (Ecosystem.PHP.equals(ecosystem) && c.regionMatches(begin, ".php", 0, 4)) {
                    if (isURL(c, begin)) {
                        return;
                    }
                } else if (Ecosystem.JAVA.equals(ecosystem) && c.regionMatches(begin, ".jsp", 0, 4)) {
                    if (isURL(c, begin)) {
                        return;
                    }
                }
            } else { // keyword

                // check if full word, i.e. typically space first and then space or dot after
                if (begin != 0) {
                    final char startChar = c.charAt(begin - 1);
                    if (startChar >= keywordPrefixes.length || !keywordPrefixes[startChar]) {
                        return;
                    }
                }
                if (end != c.length()) {
                    final char endChar = c.charAt(end);
                    if (endChar >= keywordPostfixes.length || !keywordPostfixes[endChar]) {
                        return;
                    }
                }

                final String ecosystem = value.getEcosystem();
                if (Ecosystem.NATIVE.equals(ecosystem)) { // TODO could be checked afterwards
                    if (StringUtils.contains(c, "android")) {
                        return;
                    }
                }
            }
            increment(index, ecosystemMap);
        });
    }

    private String getResult(int[] values) {
        final int best = getBestScore(values);
        if (best != -1) {
            return ECOSYSTEMS[best];
        }
        return null;
    }

    private int getBestScore(int[] values) {
        int bestIndex = -1;
        int bestScore = -1;
        for (int i = 0; i < values.length; i++) {
            if (values[i] > 0) {
                if (values[i] > bestScore) {
                    bestIndex = i;
                    bestScore = values[i];
                }
                values[i] = 0;
            }
        }
        return bestIndex;
    }
}
