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

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.io.Serializable;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Evidence is a piece of information about a Dependency.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class Evidence implements Serializable, Comparable<Evidence> {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 1L;
    /**
     * Used as starting point for generating the value in {@link #hashCode()}.
     */
    private static final int MAGIC_HASH_INIT_VALUE = 3;

    /**
     * Used as a multiplier for generating the value in {@link #hashCode()}.
     */
    private static final int MAGIC_HASH_MULTIPLIER = 67;

    /**
     * The name of the evidence.
     */
    private String name;

    /**
     * The source of the evidence.
     */
    private String source;

    /**
     * The value of the evidence.
     */
    private String value;

    /**
     * The confidence level for the evidence.
     */
    private Confidence confidence;

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
     * Get the value of value.
     *
     * @return the value of value
     */
    public String getValue() {
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
        return new HashCodeBuilder(MAGIC_HASH_INIT_VALUE, MAGIC_HASH_MULTIPLIER)
                .append(StringUtils.lowerCase(name))
                .append(StringUtils.lowerCase(source))
                .append(StringUtils.lowerCase(value))
                .append(confidence)
                .toHashCode();
    }

    /**
     * Implements equals for Evidence.
     *
     * @param that an object to check the equality of.
     * @return whether the two objects are equal.
     */
    @SuppressWarnings("deprecation")
    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (!(that instanceof Evidence)) {
            return false;
        }
        final Evidence e = (Evidence) that;

        //TODO the call to ObjectUtils.equals needs to be replaced when we
        //stop supporting Jenkins 1.6 requirement.
        return StringUtils.equalsIgnoreCase(name, e.name)
                && StringUtils.equalsIgnoreCase(source, e.source)
                && StringUtils.equalsIgnoreCase(value, e.value)
                && ObjectUtils.equals(confidence, e.confidence);
    }

    /**
     * Implementation of the comparable interface.
     *
     * @param o the evidence being compared
     * @return an integer indicating the ordering of the two objects
     */
    @SuppressWarnings("deprecation")
    @Override
    public int compareTo(Evidence o) {
        if (o == null) {
            throw new IllegalArgumentException("Unable to compare null evidence");
        }
        if (StringUtils.equalsIgnoreCase(source, o.source)) {
            if (StringUtils.equalsIgnoreCase(name, o.name)) {
                if (StringUtils.equalsIgnoreCase(value, o.value)) {
                    //TODO the call to ObjectUtils.equals needs to be replaced when we
                    //stop supporting Jenkins 1.6 requirement.
                    if (ObjectUtils.equals(confidence, o.confidence)) {
                        return 0; //they are equal
                    } else {
                        return ObjectUtils.compare(confidence, o.confidence);
                    }
                } else {
                    return compareToIgnoreCaseWithNullCheck(value, o.value);
                }
            } else {
                return compareToIgnoreCaseWithNullCheck(name, o.name);
            }
        } else {
            return compareToIgnoreCaseWithNullCheck(source, o.source);
        }
    }

    /**
     * Wrapper around
     * {@link java.lang.String#compareToIgnoreCase(java.lang.String) String.compareToIgnoreCase}
     * with an exhaustive, possibly duplicative, check against nulls.
     *
     * @param me the value to be compared
     * @param other the other value to be compared
     * @return true if the values are equal; otherwise false
     */
    private int compareToIgnoreCaseWithNullCheck(String me, String other) {
        if (me == null && other == null) {
            return 0;
        } else if (me == null) {
            return -1; //the other string is greater than me
        } else if (other == null) {
            return 1; //me is greater than the other string
        }
        return me.compareToIgnoreCase(other);
    }

    /**
     * Standard toString() implementation.
     *
     * @return the string representation of the object
     */
    @Override
    public String toString() {
        return "Evidence{" + "name=" + name + ", source=" + source + ", value=" + value + ", confidence=" + confidence + '}';
    }
}
