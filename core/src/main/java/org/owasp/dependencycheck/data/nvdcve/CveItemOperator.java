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
 * Copyright (c) 2020 OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import java.util.stream.Collectors;

import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;

/**
 *
 * Utility for processing {@linkplain DefCveItem} in order to extract key values
 * like textual description and ecosystem type.
 *
 * @author skjolber
 */
public class CveItemOperator {

    /**
     * Utility method to extract the "english" description from a given CVE
     * entry.
     *
     * @param cve a reference to a CVE object
     * @return the english description of the CVE entry
     */
    public String extractDescription(DefCveItem cve) {
        return cve.getCve().getDescription().getDescriptionData().stream().filter((desc)
                -> "en".equals(desc.getLang())).map(d
                -> d.getValue()).collect(Collectors.joining(" "));
    }

    /**
     * Attempts to determine the ecosystem based on the vendor, product and
     * targetSw.
     *
     * @param baseEcosystem the base ecosystem
     * @param vendor the vendor
     * @param product the product
     * @param targetSw the target software
     * @return the ecosystem if one is identified
     */
    private String extractEcosystem(String baseEcosystem, String vendor, String product, String targetSw) {
        if ("ibm".equals(vendor) && "java".equals(product)) {
            return "c/c++";
        }
        if ("oracle".equals(vendor) && "vm".equals(product)) {
            return "c/c++";
        }
        if ("*".equals(targetSw) || baseEcosystem != null) {
            return baseEcosystem;
        }
        return targetSw;
    }

    /**
     * Attempts to determine the ecosystem based on the vendor, product and
     * targetSw.
     *
     * @param baseEcosystem the base ecosystem
     * @param parsedCpe the CPE identifier
     * @return the ecosystem if one is identified
     */
    public String extractEcosystem(String baseEcosystem, VulnerableSoftware parsedCpe) {
        return extractEcosystem(baseEcosystem, parsedCpe.getVendor(), parsedCpe.getProduct(), parsedCpe.getTargetSw());
    }

    /**
     * Determines if the CVE description includes the ** REJECT ** text
     * indicating that the CVE was requested but ultimately rejected.
     *
     * @param description the CVE text
     * @return <code>true</code> if the CVE text includes `** REFECT **`;
     * otherwise <code>false</code>
     */
    public boolean isRejected(String description) {
        return description.startsWith("** REJECT **");
    }

}
