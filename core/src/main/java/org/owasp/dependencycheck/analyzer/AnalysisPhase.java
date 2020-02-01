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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

/**
 * An enumeration defining the phases of analysis.
 *
 * @author Jeremy Long
 */
public enum AnalysisPhase {

    /**
     * Initialization phase.
     */
    INITIAL,
    /**
     * Pre information collection phase.
     */
    PRE_INFORMATION_COLLECTION,
    /**
     * Information collection phase.
     */
    INFORMATION_COLLECTION,
    /**
     * Information collection phase 2.
     */
    INFORMATION_COLLECTION2,
    /**
     * Post information collection phase.
     */
    POST_INFORMATION_COLLECTION,
    /**
     * Pre identifier analysis phase.
     */
    PRE_IDENTIFIER_ANALYSIS,
    /**
     * Identifier analysis phase.
     */
    IDENTIFIER_ANALYSIS,
    /**
     * Post identifier analysis phase.
     */
    POST_IDENTIFIER_ANALYSIS,
    /**
     * Pre finding analysis phase.
     */
    PRE_FINDING_ANALYSIS,
    /**
     * Finding analysis phase.
     */
    FINDING_ANALYSIS,
    /**
     * Finding analysis phase 2.
     */
    FINDING_ANALYSIS_PHASE2,
    /**
     * Post analysis phase.
     */
    POST_FINDING_ANALYSIS,
    /**
     * The final analysis phase.
     */
    FINAL
}
