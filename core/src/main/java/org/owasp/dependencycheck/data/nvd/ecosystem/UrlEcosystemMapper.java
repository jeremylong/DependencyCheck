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

import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

import javax.annotation.concurrent.NotThreadSafe;

import org.owasp.dependencycheck.data.nvd.json.CVEJSON40Min11;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.Reference;
import org.owasp.dependencycheck.data.nvd.json.References;

import com.hankcs.algorithm.AhoCorasickDoubleArrayTrie;
import com.hankcs.algorithm.AhoCorasickDoubleArrayTrie.Hit;

@NotThreadSafe
public class UrlEcosystemMapper {

    /**
     * The ecosystem map.
     */
    private static final TreeMap<String, String> ECOSYSTEM_MAP;

    /**
     * TThe search array.
     */
    private final AhoCorasickDoubleArrayTrie<String> search;

    static {
        ECOSYSTEM_MAP = new TreeMap<>();
        for (UrlHostHint urlHostHint : UrlHostHint.values()) {
            ECOSYSTEM_MAP.put(urlHostHint.getValue(), urlHostHint.getEcosystem());
        }
        for (UrlPathHint urlPathHint : UrlPathHint.values()) {
            ECOSYSTEM_MAP.put(urlPathHint.getValue(), urlPathHint.getEcosystem());
        }
    }

    /**
     * Constructs a new URL ecosystem mapper.
     */
    public UrlEcosystemMapper() {
        search = new AhoCorasickDoubleArrayTrie<>();
        search.build(ECOSYSTEM_MAP);
    }

    /**
     * Determines the ecosystem for the given CVE.
     *
     * @param cve the CVE data
     * @return the ecosystem
     */
    public String getEcosystem(DefCveItem cve) {
        final References references = Optional.ofNullable(cve)
                .map(DefCveItem::getCve)
                .map(CVEJSON40Min11::getReferences)
                .orElse(null);

        if (Objects.nonNull(references)) {
            for (Reference r : references.getReferenceData()) {

                final Hit<String> ecosystem = search.findFirst(r.getUrl());
                if (ecosystem != null) {
                    return ecosystem.value;
                }
            }
        }
        return null;
    }
}
