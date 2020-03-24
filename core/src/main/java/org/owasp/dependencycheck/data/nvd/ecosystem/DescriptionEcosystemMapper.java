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

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.annotation.concurrent.NotThreadSafe;

import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.LangString;

@NotThreadSafe
public class DescriptionEcosystemMapper {

    // static fields for thread-safe + hardcoded functionality
    protected static final String[] ECOSYSTEMS;
    protected static final int[] HINT_TO_ECOSYSTEM_LOOKUP;
    protected static final TreeMap<String, EcosystemHint> ECOSYSTEM_MAP; // thread safe for reading

    // take advantage of chars also being numbers
    protected final boolean[] keywordPrefixes = getPrefixesFor(" -(\"'");
    protected final boolean[] keywordPostfixes = getPrefixesFor(" -)\"',.:;");

    protected static boolean[] getPrefixesFor(String str) {
        int max = -1;
        for (int i = 0; i < str.length(); i++) {
            if (max < str.charAt(i)) {
                max = str.charAt(i);
            }
        }

        boolean[] delimiters = new boolean[max + 1];
        for (int i = 0; i < str.length(); i++) {
            delimiters[str.charAt(i)] = true;
        }
        return delimiters;
    }

    static {
        ECOSYSTEM_MAP = new TreeMap<>();

        for (FileExtensionHint fileExtensionHint : FileExtensionHint.values()) {
            ECOSYSTEM_MAP.put(fileExtensionHint.getValue(), fileExtensionHint);
        }
        for (DescriptionKeywordHint descriptionKeywordHint : DescriptionKeywordHint.values()) {
            ECOSYSTEM_MAP.put(descriptionKeywordHint.getValue(), descriptionKeywordHint);
        }

        Map<String, Integer> ecosystemIndexes = new HashMap<>();

        HINT_TO_ECOSYSTEM_LOOKUP = new int[ECOSYSTEM_MAP.size()];

        int index = 0;
        for (Entry<String, EcosystemHint> entry : ECOSYSTEM_MAP.entrySet()) {
            EcosystemHint ecosystemHint = entry.getValue();

            Integer ecosystemIndex = ecosystemIndexes.get(ecosystemHint.getEcosystem());
            if (ecosystemIndex == null) {
                ecosystemIndex = ecosystemIndexes.size();

                ecosystemIndexes.put(ecosystemHint.getEcosystem(), ecosystemIndex);
            }

            HINT_TO_ECOSYSTEM_LOOKUP[index] = ecosystemIndex;

            index++;
        }

        ECOSYSTEMS = new String[ecosystemIndexes.size()];
        for (Entry<String, Integer> e : ecosystemIndexes.entrySet()) {
            ECOSYSTEMS[e.getValue()] = e.getKey();
        }

    }

    protected final int[] values;
    protected final StringAhoCorasickDoubleArrayTrie<EcosystemHint> ahoCorasickDoubleArrayTrie;

    public DescriptionEcosystemMapper() {
        values = new int[ECOSYSTEMS.length];
        ahoCorasickDoubleArrayTrie = toAhoCorasickDoubleArrayTrie();
    }

    protected void increment(int i) {
        values[HINT_TO_ECOSYSTEM_LOOKUP[i]]++;
    }

    protected void reset() {
        for (int i = 0; i < values.length; i++) {
            values[i] = 0;
        }
    }

    protected static StringAhoCorasickDoubleArrayTrie<EcosystemHint> toAhoCorasickDoubleArrayTrie() {
        StringAhoCorasickDoubleArrayTrie<EcosystemHint> exact = new StringAhoCorasickDoubleArrayTrie<>();
        exact.build(ECOSYSTEM_MAP);
        return exact;
    }

    public String getEcosystem(DefCveItem cve) {
        for (LangString langString : cve.getCve().getDescription().getDescriptionData()) {
            if (langString.getLang().equals("en")) {
                search(langString.getValue());
            }
        }
        return getResult();
    }

    public String getEcosystem(String multicase) {
        search(multicase);

        return getResult();
    }

    private void search(String multicase) {
        String c = multicase.toLowerCase();

        ahoCorasickDoubleArrayTrie.parseText(c, (begin, end, value, index) -> {
            if (value.getNature() == EcosystemHintNature.FILE_EXTENSION) {
                if (!isExtension(multicase, begin, end)) {
                    return;
                }

                String ecosystem = value.getEcosystem();
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
                    char startChar = c.charAt(begin - 1);
                    if (startChar >= keywordPrefixes.length || !keywordPrefixes[startChar]) {
                        return;
                    }
                }
                if (end != c.length()) {
                    char endChar = c.charAt(end);
                    if (endChar >= keywordPostfixes.length || !keywordPostfixes[endChar]) {
                        return;
                    }
                }

                String ecosystem = value.getEcosystem();
                if (Ecosystem.CMAKE.equals(ecosystem)) { // TODO could be checked afterwards
                    if (StringUtils.contains(c, "android")) {
                        return;
                    }
                }
            }
            increment(index);
        });
    }

    private String getResult() {
        int best = getBestScoreAndReset();

        if (best != -1) {
            return ECOSYSTEMS[best];
        }

        return null;
    }

    private int getBestScoreAndReset() {
        int best = -1;
        int bestScore = -1;
        for (int i = 0; i < values.length; i++) {
            if (values[i] > 0) {
                if (values[i] > bestScore) {
                    best = i;
                    bestScore = values[i];
                }
                values[i] = 0;
            }
        }
        return best;
    }

    protected static boolean isExtension(String str, int begin, int end) {
        if (str.length() != end && Character.isLetterOrDigit(str.charAt(end))) {
            return false;
        }

        return isLowercaseAscii(str, begin + 1, end);
    }

    protected static boolean isLowercaseAscii(String multicase, int start, int end) {
        for (int i = start; i < end; i++) {
            char c = multicase.charAt(i);

            if (c < 'a' || c > 'z') {
                return false;
            }
        }
        return true;
    }

    public static boolean isURL(String c, int begin) {
        begin -= 2;

        while (begin > 2) {
            begin--;

            if (c.charAt(begin) == ' ') {
                return false;
            }
            if (c.charAt(begin) == ':') {
                return c.charAt(begin + 1) == '/' && c.charAt(begin + 2) == '/';
            }
        }

        return false;
    }
}
