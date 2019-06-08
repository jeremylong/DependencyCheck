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

import java.io.Serializable;

/**
 * CVSS V2 scoring information.
 *
 * @author Jeremy Long
 */
public class CvssV2 implements Serializable {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = -2203955879356702367L;

    /**
     * CVSS Score.
     */
    private final float score;
    /**
     * CVSS Access Vector.
     */
    private final String accessVector;
    /**
     * CVSS Access Complexity.
     */
    private final String accessComplexity;
    /**
     * CVSS Authentication.
     */
    private final String authentication;
    /**
     * CVSS Confidentiality Impact.
     */
    private final String confidentialityImpact;
    /**
     * CVSS Integrity Impact.
     */
    private final String integrityImpact;
    /**
     * CVSS Availability Impact.
     */
    private final String availabilityImpact;
    /**
     * CVSS severity.
     */
    private final String severity;

    /**
     * Constructs a new CVSS V2 object.
     *
     * @param score the score
     * @param accessVector the access vector
     * @param accessComplexity the access complexity
     * @param authentication the authentication
     * @param confidentialityImpact the confidentiality impact
     * @param integrityImpact the integrity impact
     * @param availabilityImpact the availability impact
     * @param severity the severity
     */
    //CSOFF: ParameterNumber
    public CvssV2(float score, String accessVector, String accessComplexity, String authentication,
            String confidentialityImpact, String integrityImpact, String availabilityImpact, String severity) {
        this.score = score;
        this.accessVector = accessVector;
        this.accessComplexity = accessComplexity;
        this.authentication = authentication;
        this.confidentialityImpact = confidentialityImpact;
        this.integrityImpact = integrityImpact;
        this.availabilityImpact = availabilityImpact;
        this.severity = severity;
    }
    //CSON: ParameterNumber

    /**
     * Get the value of score.
     *
     * @return the value of score
     */
    public float getScore() {
        return score;
    }

    /**
     * Get the value of accessVector.
     *
     * @return the value of accessVector
     */
    public String getAccessVector() {
        return accessVector;
    }

    /**
     * Get the value of accessComplexity.
     *
     * @return the value of accessComplexity
     */
    public String getAccessComplexity() {
        return accessComplexity;
    }

    /**
     * Get the value of authentication.
     *
     * @return the value of authentication
     */
    public String getAuthentication() {
        return authentication;
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
     * Get the value of severity.
     *
     * @return the value of severity
     */
    public String getSeverity() {
        return severity;
    }

    @Override
    public String toString() {
        return String.format("/AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s",
                accessVector == null ? "" : accessVector.substring(0, 1),
                accessComplexity == null ? "" : accessComplexity.substring(0, 1),
                authentication == null ? "" : authentication.substring(0, 1),
                confidentialityImpact == null ? "" : confidentialityImpact.substring(0, 1),
                integrityImpact == null ? "" : integrityImpact.substring(0, 1),
                availabilityImpact == null ? "" : availabilityImpact.substring(0, 1));
    }
}
