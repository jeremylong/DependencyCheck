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
 * Copyright (c) 2017 Hans Aikema. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.hints;

import java.util.regex.Pattern;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Evidence;

/**
 * EvidenceMatcher can match one or more {@link Evidence}s. By using regular
 * expressions for some fields and allowing omission of Evidence fields it can
 * be used to match more than one occurrence of evidence to enable hints that
 * work for a range of similar false positives/false negatives.
 *
 * The EvidenceMatcher is used for processing Evidences of a project's
 * dependencies in conjunction with the {@code <given>} and {@code <remove>}
 * clauses of the hints file.
 *
 * @author Hans Aikema
 */
public class EvidenceMatcher {

    /**
     * The name that the {@link Evidence} should have for a match.
     */
    private final String name;

    /**
     * The source that the {@link Evidence} should have for a match. A
     * {@code null}-value is allowed and functions as a wildcard.
     */
    private final String source;

    /**
     * The value that the {@link Evidence} should have for a match.
     */
    private final String value;

    /**
     * Whether the {@link EvidenceMatcher#value} should be interpreted as a
     * regular expression.
     */
    private final boolean regex;

    /**
     * The confidence that the {@link Evidence} should have for a match. A
     * {@code null}-value is allowed and functions as a wildcard.
     */
    private final Confidence confidence;

    /**
     * Creates a new EvidenceMatcher objects.
     *
     * @param source the source of the evidence, a source that is {@code null}
     * indicates any source should match.
     * @param name the non-{@code null} name of the evidence.
     * @param value the non-{@code null} value of the evidence.
     * @param regex whether value is a regex.
     * @param confidence the confidence of the evidence, a confidence that is
     * {@code null} indicates any confidence should match.
     */
    public EvidenceMatcher(String source, String name, String value, boolean regex, Confidence confidence) {
        this.source = source;
        this.name = name;
        this.value = value;
        this.confidence = confidence;
        this.regex = regex;
    }

    /**
     * Tests whether the given Evidence matches this EvidenceMatcher.
     *
     * @param evidence the evidence to match
     * @return whether the evidence matches this matcher
     */
    public boolean matches(Evidence evidence) {
        return sourceMatches(evidence)
                && confidenceMatches(evidence)
                && name.equalsIgnoreCase(evidence.getName())
                && valueMatches(evidence);
    }

    /**
     * Standard toString() implementation.
     *
     * @return the string representation of the object
     */
    @Override
    public String toString() {
        return "HintEvidenceMatcher{" + "name=" + name + ", source=" + source + ", value=" + value
                + ", confidence=" + confidence + ", regex=" + regex + '}';
    }

    /**
     * package-private getter to allow testability of the parser without mocking.
     *
     * @return The name property
     */
    String getName() {
        return name;
    }

    /**
     * package-private getter to allow testability of the parser without mocking.
     *
     * @return The source property
     */
    String getSource() {
        return source;
    }

    /**
     * package-private getter to allow testability of the parser without mocking.
     *
     * @return The value property
     */
    String getValue() {
        return value;
    }

    /**
     * package-private getter to allow testability of the parser without mocking.
     *
     * @return The regex property
     */
    boolean isRegex() {
        return regex;
    }

    /**
     * package-private getter to allow testability of the parser without mocking.
     *
     * @return The confidence property
     */
    Confidence getConfidence() {
        return confidence;
    }

    /**
     * Checks whether the value of the evidence matches this matcher. When
     * {@link #isRegex()} is {@code true} value is used as a
     * {@link java.util.regex.Pattern} that it should match. Otherwise the value
     * must be case-insensitive equal to the evidence's value.
     *
     * @param evidence the evidence to match
     * @return <code>true</code> if the evidence matches; otherwise
     * <code>false</code>
     */
    private boolean valueMatches(Evidence evidence) {
        final boolean result;
        if (regex) {
            result = Pattern.matches(value, evidence.getValue());
        } else {
            result = value.equalsIgnoreCase(evidence.getValue());
        }
        return result;
    }

    /**
     * Checks whether the source of the evidence matches this matcher. If our
     * source is {@code null} any source in the evidence matches. Otherwise the
     * source in the evidence must be case-insensitive equal to our source.
     *
     * @param evidence The evidence to inspect
     * @return {@code true} is the source of the evidence matches, false
     * otherwise.
     */
    private boolean sourceMatches(Evidence evidence) {
        return this.source == null || source.equalsIgnoreCase(evidence.getSource());
    }

    /**
     * Checks whether the confidence of the evidence matches this matcher. If
     * our confidence is {@code null} any confidence in the evidence matches.
     * Otherwise the confidence in the evidence must be exactly equal to our
     * confidence.
     *
     * @param evidence The evidence to inspect
     * @return {@code true} is the confidence of the evidence matches, false
     * otherwise.
     */
    private boolean confidenceMatches(Evidence evidence) {
        return this.confidence == null || confidence.equals(evidence.getConfidence());
    }

}
