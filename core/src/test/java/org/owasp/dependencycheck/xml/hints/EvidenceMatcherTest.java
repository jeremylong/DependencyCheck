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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.hints;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import org.junit.Test;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Evidence;

/**
 * Unit tests for {@link EvidenceMatcher}.
 * 
 * @author Hans Aikema
 */
public class EvidenceMatcherTest {

    private static final Evidence EVIDENCE_HIGHEST = new Evidence("source", "name", "value", Confidence.HIGHEST);
    private static final Evidence EVIDENCE_HIGH = new Evidence("source", "name", "value", Confidence.HIGH);
    private static final Evidence EVIDENCE_MEDIUM = new Evidence("source", "name", "value", Confidence.MEDIUM);
    private static final Evidence EVIDENCE_MEDIUM_SECOND_SOURCE = new Evidence("source 2", "name", "value", Confidence.MEDIUM);
    private static final Evidence EVIDENCE_LOW = new Evidence("source", "name", "value", Confidence.LOW);

    private static final Evidence REGEX_EVIDENCE_HIGHEST = new Evidence("source", "name", "value 1", Confidence.HIGHEST);
    private static final Evidence REGEX_EVIDENCE_HIGH = new Evidence("source", "name", "value 2", Confidence.HIGH);
    private static final Evidence REGEX_EVIDENCE_MEDIUM = new Evidence("source", "name", "Value will not match because of case", Confidence.MEDIUM);
    private static final Evidence REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE = new Evidence("source 2", "name", "yet another value that will match", Confidence.MEDIUM);
    private static final Evidence REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE = new Evidence("source 3", "name", "and even more values to match", Confidence.MEDIUM);
    private static final Evidence REGEX_EVIDENCE_LOW = new Evidence("source", "name", "val that should not match", Confidence.LOW);

    @Test
    public void testExactMatching() throws Exception {
        final EvidenceMatcher exactMatcherHighest = new EvidenceMatcher("source", "name", "value", false, Confidence.HIGHEST);
        assertTrue("exact matcher should match EVIDENCE_HIGHEST", exactMatcherHighest.matches(EVIDENCE_HIGHEST));
        assertFalse("exact matcher should not match EVIDENCE_HIGH", exactMatcherHighest.matches(EVIDENCE_HIGH));
        assertFalse("exact matcher should not match EVIDENCE_MEDIUM", exactMatcherHighest.matches(EVIDENCE_MEDIUM));
        assertFalse("exact matcher should not match EVIDENCE_MEDIUM_SECOND_SOURCE", exactMatcherHighest.matches(EVIDENCE_MEDIUM_SECOND_SOURCE));
        assertFalse("exact matcher should not match EVIDENCE_LOW", exactMatcherHighest.matches(EVIDENCE_LOW));
    }

    @Test
    public void testWildcardConfidenceMatching() throws Exception {
        final EvidenceMatcher wildcardCofidenceMatcher = new EvidenceMatcher("source", "name", "value", false, null);
        assertTrue("wildcard confidence matcher should match EVIDENCE_HIGHEST", wildcardCofidenceMatcher.matches(EVIDENCE_HIGHEST));
        assertTrue("wildcard confidence matcher should match EVIDENCE_HIGH", wildcardCofidenceMatcher.matches(EVIDENCE_HIGH));
        assertTrue("wildcard confidence matcher should match EVIDENCE_MEDIUM", wildcardCofidenceMatcher.matches(EVIDENCE_MEDIUM));
        assertFalse("wildcard confidence matcher should not match EVIDENCE_MEDIUM_SECOND_SOURCE", wildcardCofidenceMatcher.matches(EVIDENCE_MEDIUM_SECOND_SOURCE));
        assertTrue("wildcard confidence matcher should match EVIDENCE_LOW", wildcardCofidenceMatcher.matches(EVIDENCE_LOW));
    }

    @Test
    public void testWildcardSourceMatching() throws Exception {
        final EvidenceMatcher wildcardSourceMatcher = new EvidenceMatcher(null, "name", "value", false, Confidence.MEDIUM);
        assertFalse("wildcard source matcher should not match EVIDENCE_HIGHEST", wildcardSourceMatcher.matches(EVIDENCE_HIGHEST));
        assertFalse("wildcard source matcher should not match EVIDENCE_HIGH", wildcardSourceMatcher.matches(EVIDENCE_HIGH));
        assertTrue("wildcard source matcher should match EVIDENCE_MEDIUM", wildcardSourceMatcher.matches(EVIDENCE_MEDIUM));
        assertTrue("wildcard source matcher should match EVIDENCE_MEDIUM_SECOND_SOURCE", wildcardSourceMatcher.matches(EVIDENCE_MEDIUM_SECOND_SOURCE));
        assertFalse("wildcard source matcher should not match EVIDENCE_LOW", wildcardSourceMatcher.matches(EVIDENCE_LOW));
    }

    @Test
    public void testRegExMatching() throws Exception {
        final EvidenceMatcher regexMediumMatcher = new EvidenceMatcher("source 2", "name", ".*value.*", true, Confidence.MEDIUM);
        assertFalse("regex medium matcher should not match REGEX_EVIDENCE_HIGHEST", regexMediumMatcher.matches(REGEX_EVIDENCE_HIGHEST));
        assertFalse("regex medium matcher should not match REGEX_EVIDENCE_HIGH", regexMediumMatcher.matches(REGEX_EVIDENCE_HIGH));
        assertFalse("regex medium matcher should not match REGEX_EVIDENCE_MEDIUM", regexMediumMatcher.matches(REGEX_EVIDENCE_MEDIUM));
        assertTrue("regex medium matcher should match REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE", regexMediumMatcher.matches(REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE));
        assertFalse("regex medium matcher should not match REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE", regexMediumMatcher.matches(REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE));
        assertFalse("regex medium matcher should not match REGEX_EVIDENCE_LOW", regexMediumMatcher.matches(REGEX_EVIDENCE_LOW));
    }

    @Test
    public void testRegExWildcardSourceMatching() throws Exception {
        final EvidenceMatcher regexMediumWildcardSourceMatcher = new EvidenceMatcher(null, "name", "^.*v[al]{2,2}ue[a-z ]+$", true, Confidence.MEDIUM);
        assertFalse("regex medium wildcard source matcher should not match REGEX_EVIDENCE_HIGHEST", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGHEST));
        assertFalse("regex medium wildcard source matcher should not match REGEX_EVIDENCE_HIGH", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGH));
        assertFalse("regex medium wildcard source matcher should not match REGEX_EVIDENCE_MEDIUM", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM));
        assertTrue("regex medium wildcard source matcher should match REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE));
        assertTrue("regex medium wildcard source matcher should match REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE));
        assertFalse("regex medium wildcard source matcher should not match REGEX_EVIDENCE_LOW", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_LOW));
    }

    @Test
    public void testRegExWildcardSourceWildcardConfidenceMatching() throws Exception {
        final EvidenceMatcher regexMediumWildcardSourceMatcher = new EvidenceMatcher(null, "name", ".*value.*", true, null);
        assertTrue("regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_HIGHEST", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGHEST));
        assertTrue("regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_HIGH", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGH));
        assertFalse("regex wildcard source wildcard confidence matcher should not match REGEX_EVIDENCE_MEDIUM", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM));
        assertTrue("regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE));
        assertTrue("regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE));
        assertFalse("regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_LOW", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_LOW));
    }

    @Test
    public void testRegExWildcardSourceWildcardConfidenceFourMatching() throws Exception {
        final EvidenceMatcher regexMediumWildcardSourceMatcher = new EvidenceMatcher(null, "name", "^.*[Vv][al]{2,2}[a-z ]+$", true, null);
        assertFalse("regex wildcard source wildcard confidence matcher should not match REGEX_EVIDENCE_HIGHEST", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGHEST));
        assertFalse("regex wildcard source wildcard confidence matcher should not match REGEX_EVIDENCE_HIGH", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_HIGH));
        assertTrue("regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM));
        assertTrue("regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_SECOND_SOURCE));
        assertTrue("regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_MEDIUM_THIRD_SOURCE));
        assertTrue("regex wildcard source wildcard confidence matcher should match REGEX_EVIDENCE_LOW", regexMediumWildcardSourceMatcher.matches(REGEX_EVIDENCE_LOW));
    }
}
