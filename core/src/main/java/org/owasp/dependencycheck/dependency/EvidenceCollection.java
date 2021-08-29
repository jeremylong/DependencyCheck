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
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.owasp.dependencycheck.utils.Filter;

/**
 * Used to maintain a collection of Evidence.
 *
 * @author Jeremy Long
 */
@ThreadSafe
class EvidenceCollection implements Serializable {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 867580958972090027L;
    /**
     * A collection of vendor evidence.
     */
    private final Set<Evidence> vendors = new TreeSet<>();
    /**
     * A collection of strings used to adjust Lucene's vendor term weighting.
     */
    private final Set<String> vendorWeightings = new TreeSet<>();
    /**
     * A collection of product evidence.
     */
    private final Set<Evidence> products = new TreeSet<>();
    /**
     * A collection of strings used to adjust Lucene's product term weighting.
     */
    private final Set<String> productWeightings = new TreeSet<>();
    /**
     * A collection of version evidence.
     */
    private final Set<Evidence> versions = new TreeSet<>();

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
     * Used to iterate over evidence of the specified type and confidence.
     *
     * @param type the evidence type to iterate over
     * @param confidence the confidence level for the evidence to be iterated
     * over.
     * @return Iterable&lt;Evidence&gt; an iterable collection of evidence
     */
    public synchronized Iterable<Evidence> getIterator(EvidenceType type, Confidence confidence) {
        if (null != confidence && null != type) {
            final Set<Evidence> list;

            switch (type) {
                case VENDOR:
                    list = Collections.unmodifiableSet(new TreeSet<>(vendors));
                    break;
                case PRODUCT:
                    list = Collections.unmodifiableSet(new TreeSet<>(products));
                    break;
                case VERSION:
                    list = Collections.unmodifiableSet(new TreeSet<>(versions));
                    break;
                default:
                    return null;
            }

            switch (confidence) {
                case HIGHEST:
                    return EvidenceCollection.HIGHEST_CONFIDENCE.filter(list);
                case HIGH:
                    return EvidenceCollection.HIGH_CONFIDENCE.filter(list);
                case MEDIUM:
                    return EvidenceCollection.MEDIUM_CONFIDENCE.filter(list);
                default:
                    return EvidenceCollection.LOW_CONFIDENCE.filter(list);
            }
        }
        return null;
    }

    /**
     * Adds evidence to the collection.
     *
     * @param type the type of evidence (vendor, product, version)
     * @param e Evidence
     */
    public synchronized void addEvidence(EvidenceType type, Evidence e) {
        if (null != type) {
            switch (type) {
                case VENDOR:
                    vendors.add(e);
                    break;
                case PRODUCT:
                    products.add(e);
                    break;
                case VERSION:
                    versions.add(e);
                    break;
                default:
                    break;
            }
        }
    }

    /**
     * Removes evidence from the collection.
     *
     * @param type the type of evidence (vendor, product, version)
     * @param e Evidence.
     */
    public synchronized void removeEvidence(EvidenceType type, Evidence e) {
        if (null != type) {
            switch (type) {
                case VENDOR:
                    vendors.remove(e);
                    break;
                case PRODUCT:
                    products.remove(e);
                    break;
                case VERSION:
                    versions.remove(e);
                    break;
                default:
                    break;
            }
        }
    }

    /**
     * Creates an Evidence object from the parameters and adds the resulting
     * object to the evidence collection.
     *
     * @param type the type of evidence (vendor, product, version)
     * @param source the source of the Evidence.
     * @param name the name of the Evidence.
     * @param value the value of the Evidence.
     * @param confidence the confidence of the Evidence.
     */
    public void addEvidence(EvidenceType type, String source, String name, String value, Confidence confidence) {
        final Evidence e = new Evidence(source, name, value, confidence);
        addEvidence(type, e);
    }

    /**
     * Adds term to the vendor weighting collection. The terms added here are
     * used later to boost the score of other terms. This is a way of combining
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
    public synchronized void addVendorWeighting(String str) {
        vendorWeightings.add(str.toLowerCase());
    }

    /**
     * Adds term to the product weighting collection. The terms added here are
     * used later to boost the score of other terms. This is a way of combining
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
    public synchronized void addProductWeighting(String str) {
        productWeightings.add(str.toLowerCase());
    }

    /**
     * Returns an unmodifiable set of vendor Weightings - a list of terms that
     * are believed to be of higher confidence when also found in another
     * location.
     *
     * @return an unmodifiable set of vendor weighting strings
     */
    public synchronized Set<String> getVendorWeightings() {
        return Collections.unmodifiableSet(new TreeSet<>(vendorWeightings));
    }

    /**
     * Returns an unmodifiable set of product Weightings - a list of terms that
     * are believed to be of higher confidence when also found in another
     * location.
     *
     * @return an unmodifiable set of vendor weighting strings
     */
    public synchronized Set<String> getProductWeightings() {
        return Collections.unmodifiableSet(new TreeSet<>(productWeightings));
    }

    /**
     * Returns the unmodifiable set of evidence of the given type.
     *
     * @param type the type of evidence (vendor, product, version)
     * @return the unmodifiable set of evidence
     */
    public synchronized Set<Evidence> getEvidence(EvidenceType type) {
        if (null != type) {
            switch (type) {
                case VENDOR:
                    return Collections.unmodifiableSet(new TreeSet<>(vendors));
                case PRODUCT:
                    return Collections.unmodifiableSet(new TreeSet<>(products));
                case VERSION:
                    return Collections.unmodifiableSet(new TreeSet<>(versions));
                default:
                    break;
            }
        }
        return null;
    }

    /**
     * Returns the unmodifiable set of evidence.
     *
     * @return the unmodifiable set of evidence
     */
    public synchronized Set<Evidence> getEvidence() {
        final Set<Evidence> e = new TreeSet<>(vendors);
        e.addAll(products);
        e.addAll(versions);
        return Collections.unmodifiableSet(e);
    }

    /**
     * Tests if the evidence collection contains the given evidence.
     *
     * @param type the type of evidence (vendor, product, version)
     * @param e the evidence to search
     * @return true if the evidence is found; otherwise false
     */
    public synchronized boolean contains(EvidenceType type, Evidence e) {
        if (null != type) {
            switch (type) {
                case VENDOR:
                    return vendors.contains(e);
                case PRODUCT:
                    return products.contains(e);
                case VERSION:
                    return versions.contains(e);
                default:
                    break;
            }
        }
        return false;
    }

    /**
     * Returns whether or not the collection contains evidence of a specified
     * type and confidence.
     *
     * @param type the type of evidence (vendor, product, version)
     * @param confidence A Confidence value.
     * @return boolean.
     */
    public synchronized boolean contains(EvidenceType type, Confidence confidence) {
        if (null == type) {
            return false;
        }
        final Set<Evidence> col;
        switch (type) {
            case VENDOR:
                col = vendors;
                break;
            case PRODUCT:
                col = products;
                break;
            case VERSION:
                col = versions;
                break;
            default:
                return false;
        }
        for (Evidence e : col) {
            if (e.getConfidence().equals(confidence)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns a string of evidence 'values'.
     *
     * @return a string containing the evidence.
     */
    @Override
    public synchronized String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("{vendors: [");
        for (Evidence e : this.vendors) {
            sb.append("'").append(e.getValue()).append("', ");
        }
        sb.append("],/nproducts: [");
        for (Evidence e : this.products) {
            sb.append("'").append(e.getValue()).append("', ");
        }
        sb.append("],/nversions: [");
        for (Evidence e : this.versions) {
            sb.append("'").append(e.getValue()).append("', ");
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Returns the number of elements in the EvidenceCollection.
     *
     * @return the number of elements in the collection.
     */
    public synchronized int size() {
        return vendors.size() + products.size() + versions.size();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(13, 43)
                .append(vendors)
                .append(vendorWeightings)
                .append(products)
                .append(productWeightings)
                .append(versions)
                .toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof EvidenceCollection)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final EvidenceCollection other = (EvidenceCollection) obj;
        return new EqualsBuilder()
                .append(this.vendors, other.vendors)
                .append(this.vendorWeightings, other.vendorWeightings)
                .append(this.products, other.products)
                .append(this.productWeightings, other.productWeightings)
                .append(this.versions, other.versions)
                .isEquals();
    }
}
