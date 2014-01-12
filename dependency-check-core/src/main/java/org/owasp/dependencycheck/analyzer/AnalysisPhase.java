/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

/**
 * An enumeration defining the phases of analysis.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public enum AnalysisPhase {

    /**
     * Initialization phase.
     */
    INITIAL,
    /**
     * Information collection phase.
     */
    INFORMATION_COLLECTION,
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
     * Post analysis phase.
     */
    POST_FINDING_ANALYSIS,
    /**
     * The final analysis phase.
     */
    FINAL
}
