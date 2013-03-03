/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

/**
 * An enumeration defining the phases of analysis.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public enum AnalysisPhase {

    /**
     * The first phase of analysis.
     */
    INITIAL,
    /**
     * The second phase of analysis.
     */
    INFORMATION_COLLECTION,
    /**
     * The third phase of analysis.
     */
    PRE_IDENTIFIER_ANALYSIS,
    /**
     * The fourth phase of analysis.
     */
    IDENTIFIER_ANALYSIS,
    /**
     * The fifth phase of analysis.
     */
    POST_IDENTIFIER_ANALYSIS,
    /**
     * The sixth phase of analysis.
     */
    FINDING_ANALYSIS,
    /**
     * The seventh and final phase of analysis.
     */
    FINAL
}
