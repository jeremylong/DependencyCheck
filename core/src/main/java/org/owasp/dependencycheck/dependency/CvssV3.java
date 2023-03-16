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
package org.owasp.dependencycheck.dependency;

import org.sonatype.ossindex.service.api.cvss.Cvss3Severity;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 * CVSS V3 scoring information.
 *
 * @author Jeremy Long
 */
public class CvssV3 implements Serializable {

    public static final List<String> BASE_METRICS = Arrays.asList("AV", "AC", "PR", "UI", "S", "C", "I", "A");
    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = -315810090425928920L;

    /**
     * CVSS Availability Impact.
     */
    private final String attackVector;
    /**
     * CVSS Availability Impact.
     */
    private final String attackComplexity;
    /**
     * CVSS Availability Impact.
     */
    private final String privilegesRequired;
    /**
     * CVSS Availability Impact.
     */
    private final String userInteraction;
    /**
     * CVSS Availability Impact.
     */
    private final String scope;
    /**
     * CVSS Availability Impact.
     */
    private final String confidentialityImpact;
    /**
     * CVSS Availability Impact.
     */
    private final String integrityImpact;
    /**
     * CVSS Availability Impact.
     */
    private final String availabilityImpact;
    /**
     * CVSS Base Score.
     */
    private final float baseScore;
    /**
     * CVSS Base Severity.
     */
    private final String baseSeverity;
    /**
     * CVSSv3 Base Metric exploitability score.
     */
    private final Float exploitabilityScore;
    /**
     * CVSSv3 Base Metric impact score.
     */
    private final Float impactScore;
    /**
     * CVSS version.
     */
    private final String version;

    /**
     * Constructs a new CVSS V3 object.
     *
     * @param attackVector the attack vector value
     * @param attackComplexity the attack complexity value
     * @param privilegesRequired the privileges required value
     * @param userInteraction the user interaction value
     * @param scope the scope value
     * @param confidentialityImpact the confidentiality impact value
     * @param integrityImpact the integrity impact value
     * @param availabilityImpact the availability impact value
     * @param baseScore the base score
     * @param baseSeverity the base severity
     */
    //CSOFF: ParameterNumber
    public CvssV3(String attackVector, String attackComplexity, String privilegesRequired,
            String userInteraction, String scope, String confidentialityImpact, String integrityImpact,
            String availabilityImpact, float baseScore, String baseSeverity) {
        this(attackVector, attackComplexity, privilegesRequired, userInteraction, scope, confidentialityImpact,
                integrityImpact, availabilityImpact, baseScore, baseSeverity, null, null, null);
    }

    /**
     * Constructs a new CVSS V3 object.
     *
     * @param attackVector the attack vector value
     * @param attackComplexity the attack complexity value
     * @param privilegesRequired the privileges required value
     * @param userInteraction the user interaction value
     * @param scope the scope value
     * @param confidentialityImpact the confidentiality impact value
     * @param integrityImpact the integrity impact value
     * @param availabilityImpact the availability impact value
     * @param baseScore the base score
     * @param baseSeverity the base severity
     * @param exploitabilityScore the exploitability score
     * @param impactScore the impact score
     * @param version the CVSS version
     */
    public CvssV3(String attackVector, String attackComplexity, String privilegesRequired,
            String userInteraction, String scope, String confidentialityImpact, String integrityImpact,
            String availabilityImpact, float baseScore, String baseSeverity, Float exploitabilityScore, Float impactScore, String version) {
        this.attackVector = attackVector;
        this.attackComplexity = attackComplexity;
        this.privilegesRequired = privilegesRequired;
        this.userInteraction = userInteraction;
        this.scope = scope;
        this.confidentialityImpact = confidentialityImpact;
        this.integrityImpact = integrityImpact;
        this.availabilityImpact = availabilityImpact;
        this.baseScore = baseScore;
        this.baseSeverity = baseSeverity;
        this.exploitabilityScore = exploitabilityScore;
        this.impactScore = impactScore;
        this.version = version;
    }
    //CSON: ParameterNumber

    /**
     * Constructs a new CVSS V3 object from a CVSS v3.x Vector String representation and
     * a CVSS V3 Base score.
     *
     * @param vectorString a CVSS v3 Vector String
     * @param baseScore the CVSS v3 base score
     * @throws IllegalArgumentException when the provided vectorString is not a valid
     * <a href="https://www.first.org/cvss/specification-document#Vector-String">CVSS v3.x vector string</a>.
     */
    public CvssV3(String vectorString, float baseScore) {
        if (!vectorString.startsWith("CVSS:3")) {
            throw new IllegalArgumentException("Not a valid CVSSv3 vector string: " + vectorString);
        }
        this.version = vectorString.substring(5, vectorString.indexOf('/'));
        final String[] metricStrings = vectorString.substring(vectorString.indexOf('/') + 1).split("/");
        final HashMap<String, String> metrics = new HashMap<>();
        for (int i = 0; i < metricStrings.length; i++) {
            final String[] metricKeyVal = metricStrings[i].split(":");
            if (metricKeyVal.length != 2) {
                throw new IllegalArgumentException(
                        String.format("Not a valid CVSSv3 vector string '%s', invalid metric component '%s'",
                                vectorString, metricStrings[i]));
            }
            metrics.put(metricKeyVal[0], metricKeyVal[1]);
        }
        if (!metrics.keySet().containsAll(BASE_METRICS)) {
            throw new IllegalArgumentException(
                    String.format("Not a valid CVSSv3 vector string '%s'; missing one or more required Base Metrics;",
                            vectorString));
        }
        this.attackVector = metrics.get("AV");
        this.attackComplexity = metrics.get("AC");
        this.privilegesRequired = metrics.get("PR");
        this.userInteraction = metrics.get("UI");
        this.scope = metrics.get("S");
        this.confidentialityImpact = metrics.get("C");
        this.integrityImpact = metrics.get("I");
        this.availabilityImpact = metrics.get("A");
        this.baseScore = baseScore;
        this.baseSeverity = Cvss3Severity.of(baseScore).name();
        this.exploitabilityScore = null;
        this.impactScore = null;
    }

    /**
     * Get the value of attackVector.
     *
     * @return the value of attackVector
     */
    public String getAttackVector() {
        return attackVector;
    }

    /**
     * Get the value of attackComplexity.
     *
     * @return the value of attackComplexity
     */
    public String getAttackComplexity() {
        return attackComplexity;
    }

    /**
     * Get the value of privilegesRequired.
     *
     * @return the value of privilegesRequired
     */
    public String getPrivilegesRequired() {
        return privilegesRequired;
    }

    /**
     * Get the value of userInteraction.
     *
     * @return the value of userInteraction
     */
    public String getUserInteraction() {
        return userInteraction;
    }

    /**
     * Get the value of scope.
     *
     * @return the value of scope
     */
    public String getScope() {
        return scope;
    }

    /**
     * Get the value of confidentialityImpact.
     *
     * @return the value of confidentialityImpact
     */
    public String getConfidentialityImpact() {
        return confidentialityImpact;
    }

    /**
     * Get the value of integrityImpact.
     *
     * @return the value of integrityImpact
     */
    public String getIntegrityImpact() {
        return integrityImpact;
    }

    /**
     * Get the value of availabilityImpact.
     *
     * @return the value of availabilityImpact
     */
    public String getAvailabilityImpact() {
        return availabilityImpact;
    }

    /**
     * Get the value of baseScore.
     *
     * @return the value of baseScore
     */
    public float getBaseScore() {
        return baseScore;
    }

    /**
     * Get the value of baseSeverity.
     *
     * @return the value of baseSeverity
     */
    public String getBaseSeverity() {
        return baseSeverity;
    }

    /**
     * Get the value of version.
     *
     * @return the value of version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Returns the exploitabilityScore for the vulnerability.
     *
     * @return the exploitabilityScore
     */
    public Float getexploitabilityScore() {
        return exploitabilityScore;
    }

    /**
     * Returns the impactScore for the vulnerability.
     *
     * @return the impactScore
     */
    public Float getimpactScore() {
        return impactScore;
    }

    @Override
    public String toString() {
        return String.format("CVSS:%s/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
                version == null ? "" : version,
                attackVector == null ? "" : attackVector.substring(0, 1),
                attackComplexity == null ? "" : attackComplexity.substring(0, 1),
                privilegesRequired == null ? "" : privilegesRequired.substring(0, 1),
                userInteraction == null ? "" : userInteraction.substring(0, 1),
                scope == null ? "" : scope.substring(0, 1),
                confidentialityImpact == null ? "" : confidentialityImpact.substring(0, 1),
                integrityImpact == null ? "" : integrityImpact.substring(0, 1),
                availabilityImpact == null ? "" : availabilityImpact.substring(0, 1));
    }

}
