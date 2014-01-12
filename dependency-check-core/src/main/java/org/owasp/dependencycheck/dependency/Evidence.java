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
package org.owasp.dependencycheck.dependency;

/**
 * Evidence is a piece of information about a Dependency.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class Evidence implements Comparable<Evidence> {

    /**
     * The confidence that the evidence is "high" quality.
     */
    public enum Confidence {

        /**
         * High confidence evidence.
         */
        HIGHEST,
        /**
         * High confidence evidence.
         */
        HIGH,
        /**
         * Medium confidence evidence.
         */
        MEDIUM,
        /**
         * Low confidence evidence.
         */
        LOW
    }

    /**
     * Creates a new Evidence object.
     */
    public Evidence() {
    }

    /**
     * Creates a new Evidence objects.
     *
     * @param source the source of the evidence.
     * @param name the name of the evidence.
     * @param value the value of the evidence.
     * @param confidence the confidence of the evidence.
     */
    public Evidence(String source, String name, String value, Confidence confidence) {
        this.source = source;
        this.name = name;
        this.value = value;
        this.confidence = confidence;
    }
    /**
     * The name of the evidence.
     */
    private String name;

    /**
     * Get the value of name.
     *
     * @return the value of name
     */
    public String getName() {
        return name;
    }

    /**
     * Set the value of name.
     *
     * @param name new value of name
     */
    public void setName(String name) {
        this.name = name;
    }
    /**
     * The source of the evidence.
     */
    private String source;

    /**
     * Get the value of source.
     *
     * @return the value of source
     */
    public String getSource() {
        return source;
    }

    /**
     * Set the value of source.
     *
     * @param source new value of source
     */
    public void setSource(String source) {
        this.source = source;
    }
    /**
     * The value of the evidence.
     */
    private String value;

    /**
     * Get the value of value.
     *
     * @return the value of value
     */
    public String getValue() {
        used = true;
        return value;
    }

    /**
     * Get the value of value. If setUsed is set to false this call to get will
     * not mark the evidence as used.
     *
     * @param setUsed whether or not this call to getValue should cause the used
     * flag to be updated
     * @return the value of value
     */
    public String getValue(Boolean setUsed) {
        used = used || setUsed;
        return value;
    }

    /**
     * Set the value of value.
     *
     * @param value new value of value
     */
    public void setValue(String value) {
        this.value = value;
    }
    /**
     * A value indicating if the Evidence has been "used" (aka read).
     */
    private boolean used;

    /**
     * Get the value of used.
     *
     * @return the value of used
     */
    public boolean isUsed() {
        return used;
    }

    /**
     * Set the value of used.
     *
     * @param used new value of used
     */
    public void setUsed(boolean used) {
        this.used = used;
    }
    /**
     * The confidence level for the evidence.
     */
    private Confidence confidence;

    /**
     * Get the value of confidence.
     *
     * @return the value of confidence
     */
    public Confidence getConfidence() {
        return confidence;
    }

    /**
     * Set the value of confidence.
     *
     * @param confidence new value of confidence
     */
    public void setConfidence(Confidence confidence) {
        this.confidence = confidence;
    }

    /**
     * Implements the hashCode for Evidence.
     *
     * @return hash code.
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 67 * hash + (this.name != null ? this.name.hashCode() : 0);
        hash = 67 * hash + (this.source != null ? this.source.hashCode() : 0);
        hash = 67 * hash + (this.value != null ? this.value.hashCode() : 0);
        hash = 67 * hash + (this.confidence != null ? this.confidence.hashCode() : 0);
        return hash;
    }

    /**
     * Implements equals for Evidence.
     *
     * @param that an object to check the equality of.
     * @return whether the two objects are equal.
     */
    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (!(that instanceof Evidence)) {
            return false;
        }
        final Evidence e = (Evidence) that;

        return testEquality(name, e.name) && testEquality(source, e.source) && testEquality(value, e.value)
                && (confidence == null ? e.confidence == null : confidence == e.confidence);
    }

    /**
     * Simple equality test for use within the equals method. This does a case
     * insensitive compare.
     *
     * @param l a string to compare.
     * @param r another string to compare.
     * @return whether the two strings are the same.
     */
    private boolean testEquality(String l, String r) {
        return l == null ? r == null : l.equalsIgnoreCase(r);
    }

    /**
     * Implementation of the comparable interface.
     *
     * @param o the evidence being compared
     * @return an integer indicating the ordering of the two objects
     */
    public int compareTo(Evidence o) {
        if (source.equals(o.source)) {
            if (name.equals(o.name)) {
                if (value.equals(o.value)) {
                    if (confidence.equals(o.confidence)) {
                        return 0; //they are equal
                    } else {
                        return confidence.compareTo(o.confidence);
                    }
                } else {
                    return value.compareToIgnoreCase(o.value);
                }
            } else {
                return name.compareToIgnoreCase(o.name);
            }
        } else {
            return source.compareToIgnoreCase(o.source);
        }
    }
}
