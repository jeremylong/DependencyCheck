/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.dependency;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;
import org.owasp.dependencycheck.utils.Filter;

/**
 * Used to maintain a collection of Evidence.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class EvidenceCollection implements Iterable<Evidence> {

    /**
     * Used to iterate over high confidence evidence contained in the
     * collection.
     */
    private static final Filter<Evidence> HIGH_CONFIDENCE =
            new Filter<Evidence>() {

                public boolean passes(Evidence evidence) {
                    return evidence.getConfidence() == Evidence.Confidence.HIGH;
                }
            };
    /**
     * Used to iterate over medium confidence evidence contained in the
     * collection.
     */
    private static final Filter<Evidence> MEDIUM_CONFIDENCE =
            new Filter<Evidence>() {

                public boolean passes(Evidence evidence) {
                    return evidence.getConfidence() == Evidence.Confidence.MEDIUM;
                }
            };
    /**
     * Used to iterate over low confidence evidence contained in the collection.
     */
    private static final Filter<Evidence> LOW_CONFIDENCE =
            new Filter<Evidence>() {

                public boolean passes(Evidence evidence) {
                    return evidence.getConfidence() == Evidence.Confidence.LOW;
                }
            };
    /**
     * Used to iterate over evidence that has was used (aka read) from the
     * collection.
     */
    private static final Filter<Evidence> EVIDENCE_USED =
            new Filter<Evidence>() {

                public boolean passes(Evidence evidence) {
                    return evidence.isUsed();
                }
            };

    /**
     * Used to iterate over evidence of the specified confidence.
     *
     * @param confidence the confidence level for the evidence to be iterated
     * over.
     * @return Iterable<Evidence>.
     */
    public final Iterable<Evidence> iterator(Evidence.Confidence confidence) {
        if (confidence == Evidence.Confidence.HIGH) {
            return EvidenceCollection.HIGH_CONFIDENCE.filter(this.list);
        } else if (confidence == Evidence.Confidence.MEDIUM) {
            return EvidenceCollection.MEDIUM_CONFIDENCE.filter(this.list);
        } else {
            return EvidenceCollection.LOW_CONFIDENCE.filter(this.list);
        }
    }
    /**
     * A collection of evidence.
     */
    private final Set<Evidence> list;
    /**
     * A collection of strings used to adjust Lucene's term weighting.
     */
    private final Set<String> weightedStrings;

    /**
     * Creates a new EvidenceCollection.
     */
    public EvidenceCollection() {
        list = new TreeSet<Evidence>();
        weightedStrings = new HashSet<String>();
    }

    /**
     * Adds evidence to the collection.
     *
     * @param e Evidence.
     */
    public void addEvidence(Evidence e) {
        list.add(e);
    }

    /**
     * Creates an Evidence object from the parameters and adds the resulting
     * object to the collection.
     *
     * @param source the source of the Evidence.
     * @param name the name of the Evidence.
     * @param value the value of the Evidence.
     * @param confidence the confidence of the Evidence.
     */
    public void addEvidence(String source, String name, String value, Evidence.Confidence confidence) {
        final Evidence e = new Evidence(source, name, value, confidence);
        addEvidence(e);
    }

    /**
     * Adds term to the weighting collection. The terms added here are used
     * later to boost the score of other terms. This is a way of combining
     * evidence from multiple sources to boost the confidence of the given
     * evidence.
     *
     * Example: The term 'Apache' is found in the manifest of a JAR and is added
     * to the Collection. When we parse the package names within the JAR file we
     * may add these package names to the "weighted" strings collection to boost
     * the score in the Lucene query. That way when we construct the Lucene
     * query we find the term Apache in the collection AND in the weighted
     * strings; as such, we will boost the confidence of the term Apache.
     *
     * @param str to add to the weighting collection.
     */
    public void addWeighting(String str) {
        weightedStrings.add(str);
    }

    /**
     * Returns a set of Weightings - a list of terms that are believed to be of
     * higher confidence when also found in another location.
     *
     * @return Set<String>
     */
    public Set<String> getWeighting() {
        return weightedStrings;
    }

    /**
     * Returns the set of evidence.
     *
     * @return the set of evidence.
     */
    public Set<Evidence> getEvidence() {
        return list;
    }

    /**
     * Implements the iterator interface for the Evidence Collection.
     *
     * @return an Iterator<Evidence>.
     */
    public Iterator<Evidence> iterator() {
        return list.iterator();
    }

    /**
     * Used to determine if a given string was used (aka read).
     *
     * @param text the string to search for.
     * @return whether or not the string was used.
     */
    public boolean containsUsedString(String text) {
        if (text == null) {
            return false;
        }
        final String textToTest = text.toLowerCase();

        for (Evidence e : this.list) {
            if (e.isUsed() && e.getValue().toLowerCase().contains(textToTest)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns whether or not the collection contains evidence of a specified
     * Confidence.
     *
     * @param confidence A Confidence value.
     * @return boolean.
     */
    public boolean contains(Evidence.Confidence confidence) {
        for (Evidence e : list) {
            if (e.getConfidence().equals(confidence)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Merges multiple EvidenceCollections together, only merging evidence that
     * was used, into a new EvidenceCollection.
     *
     * @param ec One or more EvidenceCollections.
     * @return a new EvidenceCollection containing the used evidence.
     */
    public static EvidenceCollection mergeUsed(EvidenceCollection... ec) {
        final EvidenceCollection ret = new EvidenceCollection();
        for (EvidenceCollection col : ec) {
            for (Evidence e : col.list) {
                if (e.isUsed()) {
                    ret.addEvidence(e);
                }
            }
        }
        return ret;
    }

    /**
     * Merges multiple EvidenceCollections together.
     *
     * @param ec One or more EvidenceCollections.
     * @return a new EvidenceCollection.
     */
    public static EvidenceCollection merge(EvidenceCollection... ec) {
        final EvidenceCollection ret = new EvidenceCollection();
        for (EvidenceCollection col : ec) {
            ret.list.addAll(col.list);
            ret.weightedStrings.addAll(col.weightedStrings);
        }
        return ret;
    }

    /**
     * Returns a string of evidence 'values'.
     *
     * @return a string containing the evidence.
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        for (Evidence e : this.list) {
            sb.append(e.getValue()).append(' ');
        }
        return sb.toString();
    }

    /**
     * Returns the number of elements in the EvidenceCollection.
     *
     * @return the number of elements in the collection.
     */
    public int size() {
        return list.size();
    }
}
