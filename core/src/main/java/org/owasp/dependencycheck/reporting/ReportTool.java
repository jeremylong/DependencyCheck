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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.CpeIdentifier;
import org.owasp.dependencycheck.dependency.naming.GenericIdentifier;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.utils.SeverityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.exceptions.CpeEncodingException;
import us.springett.parsers.cpe.util.Convert;

/**
 * Utilities to format items in the Velocity reports.
 *
 * @author Jeremy Long
 */
public class ReportTool {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ReportTool.class);

    /**
     * Converts an identifier into the Suppression string when possible.
     *
     * @param id the Identifier to format
     * @return the formatted suppression string when possible; otherwise
     * <code>null</code>.
     */
    public String identifierToSuppressionId(Identifier id) {
        if (id instanceof PurlIdentifier) {
            final PurlIdentifier purl = (PurlIdentifier) id;
            return purl.toString();
        } else if (id instanceof CpeIdentifier) {
            try {
                final CpeIdentifier cpeId = (CpeIdentifier) id;
                final Cpe cpe = cpeId.getCpe();
                return String.format("cpe:/%s:%s:%s", Convert.wellFormedToCpeUri(cpe.getPart()),
                        Convert.wellFormedToCpeUri(cpe.getWellFormedVendor()),
                        Convert.wellFormedToCpeUri(cpe.getWellFormedProduct()));
            } catch (CpeEncodingException ex) {
                LOGGER.debug("Unable to convert to cpe URI", ex);
            }
        } else if (id instanceof GenericIdentifier) {
            return id.getValue();
        }
        return null;
    }

    /**
     * Estimates the CVSS V2 score for the given severity.
     *
     * @param severity the text representation of a score
     * @return the estimated score
     */
    public float estimateSeverity(String severity) {
        return SeverityUtil.estimateCvssV2(severity);
    }

    /**
     * Creates a list of SARIF rules for the SARIF report.
     *
     * @param dependencies the list of dependencies to extract rules from
     * @return the list of SARIF rules
     */
    public Collection<SarifRule> convertToSarifRules(List<Dependency> dependencies) {
        final Map<String, SarifRule> rules = new HashMap<>();
        for (Dependency d : dependencies) {
            for (Vulnerability v : d.getVulnerabilities()) {
                if (!rules.containsKey(v.getName())) {
                    final SarifRule r = new SarifRule(v.getName(),
                            buildShortDescription(d, v),
                            v.getDescription(),
                            v.getSource().name(),
                            v.getCvssV2(),
                            v.getCvssV3());
                    rules.put(v.getName(), r);
                }
            }
        }
        return rules.values();
    }

    private String determineScore(Vulnerability vuln) {
        if (vuln.getUnscoredSeverity() != null) {
            if ("0.0".equals(vuln.getUnscoredSeverity())) {
                return "Unknown";
            } else {
                return normalizeSeverity(vuln.getUnscoredSeverity().toLowerCase());
            }
        } else if (vuln.getCvssV3() != null && vuln.getCvssV3().getBaseSeverity() != null) {
            return normalizeSeverity(vuln.getCvssV3().getBaseSeverity().toLowerCase());
        } else if (vuln.getCvssV2() != null && vuln.getCvssV2().getSeverity() != null) {
            return normalizeSeverity(vuln.getCvssV2().getSeverity());
        }
        return "Unknown";
    }

    private String normalizeSeverity(String sev) {
        switch (sev) {
            case "critical":
                return "Critical";
            case "high":
                return "High";
            case "medium":
                return "Medium";
            case "moderate":
                return "Medium";
            case "low":
                return "Low";
            case "informational":
                return "Low";
            case "info":
                return "Low";
            default:
                return "Unknown";
        }
    }

    /**
     * Builds the short description for the Sarif format.
     *
     * @param d the dependency
     * @param vuln the vulnerability
     * @return the short description
     */
    private String buildShortDescription(Dependency d, Vulnerability vuln) {
        final StringBuilder sb = new StringBuilder();
        sb.append(determineScore(vuln))
                .append(" severity - ")
                .append(vuln.getName());
        if (vuln.getCwes() != null && !vuln.getCwes().isEmpty()) {
            final String cwe = vuln.getCwes().getFullCwes().values().iterator().next();
            if (cwe != null && !"NVD-CWE-Other".equals(cwe) && !"NVD-CWE-noinfo".equals(cwe)) {
                sb.append(" ").append(cwe);
            }
        }
        sb.append(" vulnerability in ");
        if (d.getSoftwareIdentifiers() != null && !d.getSoftwareIdentifiers().isEmpty()) {
            sb.append(d.getSoftwareIdentifiers().iterator().next());
        } else {
            sb.append(d.getDisplayFileName());
        }
        return sb.toString();
    }

}
