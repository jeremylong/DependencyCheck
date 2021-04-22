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

import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.concurrent.NotThreadSafe;
import org.owasp.dependencycheck.data.nvd.json.CpeMatchStreamCollector;
import org.owasp.dependencycheck.data.nvd.json.DefCpeMatch;

import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.NodeFlatteningCollector;

/**
 * Utility for mapping CVEs to their ecosystems.
 * <br><br>
 * Follows a best effort approach:
 * <ul>
 * <li>scans through the description for known keywords or file extensions;
 * alternatively </li>
 * <li>attempts looks at the reference-data URLs for known hosts or path / query
 * strings.</li>
 * </ul>
 * This class is not thread safe and must be instantiated on a per-thread basis.
 *
 * @author skjolber
 */
@NotThreadSafe
public class CveEcosystemMapper {

    /**
     * A reference to the Description Ecosystem Mapper.
     */
    private final DescriptionEcosystemMapper descriptionEcosystemMapper = new DescriptionEcosystemMapper();
    /**
     * A reference to the URL Ecosystem Mapper.
     */
    private final UrlEcosystemMapper urlEcosystemMapper = new UrlEcosystemMapper();

    /**
     * Analyzes the description and associated URLs to determine if the
     * vulnerability/software is for a specific known ecosystem. The ecosystem
     * can be used later for filtering CPE matches.
     *
     * @param cve the item to be analyzed
     * @return the ecosystem if one could be identified; otherwise
     * <code>null</code>
     */
    public String getEcosystem(DefCveItem cve) {
        //if there are multiple vendor/product pairs we don't know if they are
        //all the same ecosystem.
        if (hasMultipleVendorProductConfigurations(cve)) {
            return null;
        }
        final String ecosystem = descriptionEcosystemMapper.getEcosystem(cve);
        if (ecosystem != null) {
            return ecosystem;
        }
        return urlEcosystemMapper.getEcosystem(cve);
    }

    /**
     * Analyzes the vulnerable configurations to see if the CVE applies to only
     * a single vendor/product pair.
     *
     * @param cve the item to be analyzed
     * @return the ecosystem if one could be identified; otherwise
     * <code>null</code>
     */
    private boolean hasMultipleVendorProductConfigurations(DefCveItem cve) {
        final List<DefCpeMatch> cpeEntries = cve.getConfigurations().getNodes().stream()
                .collect(NodeFlatteningCollector.getInstance())
                .collect(CpeMatchStreamCollector.getInstance())
                .filter(defCpeMatch -> defCpeMatch.getCpe23Uri() != null)
                .collect(Collectors.toList());
        if (!cpeEntries.isEmpty() && cpeEntries.size() > 1) {
            final DefCpeMatch firstMatch = cpeEntries.get(0);
            final String uri = firstMatch.getCpe23Uri();
            final int pos = uri.indexOf(":", uri.indexOf(":", 10) + 1);
            final String match = uri.substring(0, pos + 1);
            return !cpeEntries.stream().allMatch(e -> e.getCpe23Uri().startsWith(match));
        }
        return false;
    }
}
