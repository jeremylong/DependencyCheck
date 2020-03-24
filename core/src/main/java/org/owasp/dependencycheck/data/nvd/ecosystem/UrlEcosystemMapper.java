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

import java.util.TreeMap;

import javax.annotation.concurrent.NotThreadSafe;

import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.Reference;

import com.hankcs.algorithm.AhoCorasickDoubleArrayTrie;
import com.hankcs.algorithm.AhoCorasickDoubleArrayTrie.Hit;

@NotThreadSafe
public class UrlEcosystemMapper {

    protected static final TreeMap<String, String> ECOSYSTEM_MAP;

    protected AhoCorasickDoubleArrayTrie<String> search;

    static {
        ECOSYSTEM_MAP = new TreeMap<>();
        for (UrlHostHint urlHostHint : UrlHostHint.values()) {
            ECOSYSTEM_MAP.put(urlHostHint.getValue(), urlHostHint.getEcosystem());
        }
        for (UrlPathHint urlPathHint : UrlPathHint.values()) {
            ECOSYSTEM_MAP.put(urlPathHint.getValue(), urlPathHint.getEcosystem());
        }
    }

    public UrlEcosystemMapper() {
        search = new AhoCorasickDoubleArrayTrie<>();
        search.build(ECOSYSTEM_MAP);
    }

    public String getEcosystem(DefCveItem cve) {
        for (Reference r : cve.getCve().getReferences().getReferenceData()) {

            Hit<String> ecosystem = search.findFirst(r.getUrl());
            if (ecosystem != null) {
                return ecosystem.value;
            }
        }
        return null;
    }
}
