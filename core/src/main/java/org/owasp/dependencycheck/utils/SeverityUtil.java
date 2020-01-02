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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

/**
 * Utility to estimate severity level scores.
 *
 * @author Jeremy Long
 */
public final class SeverityUtil {

    /**
     * Private constructor for a utility class.
     */
    private SeverityUtil() {
        //noop
    }

    /**
     * Estimates the CVSS V2 Score based on a given severity. The implementation
     * will default to 3.9 if no recognized "severity" level is given (critical,
     * high, low).
     *
     * @param severity the severity text (e.g. "medium")
     * @return a score from 0 to 10
     */
    public static float estimateCvssV2(String severity) {
        switch (severity == null ? "none" : severity.toLowerCase()) {
            case "critical":
            case "high":
                return 10.0f;
            case "moderate":
            case "medium":
                return 6.9f;
            case "info":
            case "informational":
                return 0.0f;
            case "low":
            case "unknown":
            case "none":
            default:
                return 3.9f;
        }
    }
}
