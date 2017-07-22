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
package org.owasp.dependencycheck.dependency;

import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.Filter;
import org.owasp.dependencycheck.utils.UrlStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Used to maintain a collection of Evidence.
 *
 * @author Jeremy Long
 */
public class EvidenceCollection implements Serializable, Iterable<Evidence> {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 1L;
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EvidenceCollection.class);
    /**
     * A collection of evidence.
     */
    private final Set<Evidence> list;
    /**
     * A collection of strings used to adjust Lucene's term weighting.
     */
    private final Set<String> weightedStrings;

    /**
     * Used to iterate over highest confidence evidence contained in the
     * collection.
     */
    private static final Filter<Evidence> HIGHEST_CONFIDENCE = new Filter<Evidence>() {
        @Override
        public boolean passes(Evidence evidence) {
            return evidence.getConfidence() == Confidence.HIGHEST;
        }
    };
    /**
     * Used to iterate over high confidence evidence contained in the
     * collection.
     */
    private static final Filter<Evidence> HIGH_CONFIDENCE = new Filter<Evidence>() {
        @Override
        public boolean passes(Evidence evidence) {
            return evidence.getConfidence() == Confidence.HIGH;
        }
    };
    /**
     * Used to iterate over medium confidence evidence contained in the
     * collection.
     */
    private static final Filter<Evidence> MEDIUM_CONFIDENCE = new Filter<Evidence>() {
        @Override
        public boolean passes(Evidence evidence) {
            return evidence.getConfidence() == Confidence.MEDIUM;
        }
    };
    /**
     * Used to iterate over low confidence evidence contained in the collection.
     */
    private static final Filter<Evidence> LOW_CONFIDENCE = new Filter<Evidence>() {
        @Override
        public boolean passes(Evidence evidence) {
            return evidence.getConfidence() == Confidence.LOW;
        }
    };
    /**
     * Used to iterate over evidence that has was used (aka read) from the
     * collection.
     */
    private static final Filter<Evidence> EVIDENCE_USED = new Filter<Evidence>() {
        @Override
        public boolean passes(Evidence evidence) {
            return evidence.isUsed();
        }
    };

    /**
     * Used to iterate over evidence of the specified confidence.
     *
     * @param confidence the confidence level for the evidence to be iterated
     * over.
     * @return Iterable&lt;Evidence&gt; an iterable collection of evidence
     */
    public final Iterable<Evidence> iterator(Confidence confidence) {
        if (null != confidence) {
            switch (confidence) {
                case HIGHEST:
                    return EvidenceCollection.HIGHEST_CONFIDENCE.filter(this.list);
                case HIGH:
                    return EvidenceCollection.HIGH_CONFIDENCE.filter(this.list);
                case MEDIUM:
                    return EvidenceCollection.MEDIUM_CONFIDENCE.filter(this.list);
                default:
                    return EvidenceCollection.LOW_CONFIDENCE.filter(this.list);
            }
        }
        return null;
    }

    /**
     * Creates a new EvidenceCollection.
     */
    public EvidenceCollection() {
        list = new TreeSet<>();
        weightedStrings = new HashSet<>();
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
    public void addEvidence(String source, String name, String value, Confidence confidence) {
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
     * @return Set&lt;String&gt;
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
     * Returns the set of evidence from a given source.
     *
     * @param source the source of the evidence
     * @return the set of evidence.
     */
    public Set<Evidence> getEvidence(String source) {
        if (source == null) {
            return null;
        }
        final Set<Evidence> ret = new HashSet<>();
        for (Evidence e : list) {
            if (source.equals(e.getSource())) {
                ret.add(e);
            }
        }
        return ret;
    }

    /**
     * Returns the set of evidence from a given source and name.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence to return
     * @return the set of evidence.
     */
    public Set<Evidence> getEvidence(String source, String name) {
        if (source == null || name == null) {
            return null;
        }
        final Set<Evidence> ret = new HashSet<>();
        for (Evidence e : list) {
            if (source.equals(e.getSource()) && name.equals(e.getName())) {
                ret.add(e);
            }
        }
        return ret;
    }

    /**
     * Implements the iterator interface for the Evidence Collection.
     *
     * @return an Iterator&lt;Evidence&gt;
     */
    @Override
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

        for (Evidence e : EvidenceCollection.EVIDENCE_USED.filter(this)) {
            //TODO consider changing the regex to only compare alpha-numeric (i.e. strip everything else)
            final String item = e.getValue();
            if (item != null) {
                final String uc = urlCorrection(item.toLowerCase());
                if (uc != null) {
                    final String value = uc.replaceAll("[\\s_-]", "");
                    if (value.contains(textToTest)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Used to determine if a given version was used (aka read) from the
     * EvidenceCollection.
     *
     * @param version the version to search for within the collected evidence.
     * @return whether or not the string was used.
     */
    public boolean containsUsedVersion(DependencyVersion version) {
        if (version == null) {
            return false;
        }

        for (Evidence e : EvidenceCollection.EVIDENCE_USED.filter(this)) {
            final DependencyVersion value = DependencyVersionUtil.parseVersion(e.getValue());
            if (value != null && value.matchesAtLeastThreeLevels(version)) {
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
    public boolean contains(Confidence confidence) {
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
     * Merges multiple EvidenceCollections together; flattening all of the
     * evidence items by removing the confidence.
     *
     * @param ec One or more EvidenceCollections
     * @return new set of evidence resulting from merging the evidence in the
     * collections
     */
    public static Set<Evidence> mergeForDisplay(EvidenceCollection... ec) {
        final Set<Evidence> ret = new TreeSet<>();
        for (EvidenceCollection col : ec) {
            for (Evidence e : col) {
                //if (e.isUsed()) {
                final Evidence newEvidence = new Evidence(e.getSource(), e.getName(), e.getValue(), null);
                newEvidence.setUsed(true);
                ret.add(newEvidence);
                //}
            }
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

    /**
     * <p>
     * Takes a string that may contain a fully qualified domain and it will
     * return the string having removed the query string, the protocol, the
     * sub-domain of 'www', and the file extension of the path.</p>
     * <p>
     * This is useful for checking if the evidence contains a specific string.
     * The presence of the protocol, file extension, etc. may produce false
     * positives.
     *
     * <p>
     * Example, given the following input:</p>
     * <code>'Please visit https://www.owasp.com/path1/path2/file.php?id=439'</code>
     * <p>
     * The function would return:</p>
     * <code>'Please visit owasp path1 path2 file'</code>
     *
     * @param value the value that may contain a url
     * @return the modified string
     */
    private String urlCorrection(String value) {
        if (value == null || !UrlStringUtils.containsUrl(value)) {
            return value;
        }
        final StringBuilder sb = new StringBuilder(value.length());
        final String[] parts = value.split("\\s");
        for (String part : parts) {
            if (UrlStringUtils.isUrl(part)) {
                try {
                    final List<String> data = UrlStringUtils.extractImportantUrlData(part);
                    sb.append(' ').append(StringUtils.join(data, ' '));
                } catch (MalformedURLException ex) {
                    LOGGER.debug("error parsing {}", part, ex);
                    sb.append(' ').append(part);
                }
            } else {
                sb.append(' ').append(part);
            }
        }
        return sb.toString().trim();
    }
}
