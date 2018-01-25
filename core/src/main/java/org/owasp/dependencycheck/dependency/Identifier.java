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
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 * In identifier such as a CPE or dependency coordinates (i.e. GAV).
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class Identifier implements Serializable, Comparable<Identifier> {

    //<editor-fold defaultstate="collapsed" desc="fields">
    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = 1L;
    /**
     * The confidence that this is the correct identifier.
     */
    private Confidence confidence;
    /**
     * The value of the identifier
     */
    private String value;
    /**
     * The URL for the identifier.
     */
    private String url;
    /**
     * The type of the identifier.
     */
    private String type;
    /**
     * A description of the identifier.
     */
    private String description;
    /**
     * Notes about the vulnerability. Generally used for suppression
     * information.
     */
    private String notes;
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="getters/setters">
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
     * Get the value of url.
     *
     * @return the value of url
     */
    public String getUrl() {
        return url;
    }

    /**
     * Set the value of url.
     *
     * @param url new value of url
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Get the value of type.
     *
     * @return the value of type
     */
    public String getType() {
        return type;
    }

    /**
     * <p>
     * Set the value of type.</p><p>
     * Example would be "CPE".</p>
     *
     * @param type new value of type
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * Get the value of description.
     *
     * @return the value of description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Set the value of description.
     *
     * @param description new value of description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Get the value of notes from suppression notes.
     *
     * @return the value of notes
     */
    public String getNotes() {
        return notes;
    }

    /**
     * Set the value of notes.
     *
     * @param notes new value of notes
     */
    public void setNotes(String notes) {
        this.notes = notes;
    }
    //</editor-fold>

    /**
     * Default constructor. Should only be used for automatic class creation as
     * is the case with many XML parsers (for the parsing of the
     * Dependency-Check XML report). For all other use-cases, please use the
     * non-default constructors.
     */
    public Identifier() {
    }

    /**
     * Constructs a new Identifier with the specified data.
     *
     * @param type the identifier type.
     * @param value the identifier value.
     * @param url the identifier URL.
     */
    public Identifier(String type, String value, String url) {
        this.type = type;
        this.value = value;
        this.url = url;
    }

    /**
     * Constructs a new Identifier with the specified data.
     *
     * @param type the identifier type.
     * @param value the identifier value.
     * @param url the identifier URL.
     * @param description the description of the identifier.
     */
    public Identifier(String type, String value, String url, String description) {
        this(type, value, url);
        this.description = description;
    }

    /**
     * Basic implementation of equals. This only compares the type and value of
     * the identifier.
     * @param obj the identifier to compare
     * @return true if the objects are equal
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final Identifier other = (Identifier) obj;

        return new EqualsBuilder()
                .append(this.type, other.type)
                .append(this.value, other.value)
                .isEquals();
    }

    /**
     * Basic implementation of hasCode. Note, this only takes into consideration
     * the type and value of the identifier.
     * @return the hash code
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(5, 49)
                .append(type)
                .append(value)
                .toHashCode();
    }

    /**
     * Standard implementation of toString; displays identifier value and type.
     *
     * @return a String representation of the object
     */
    @Override
    public String toString() {
        return "Identifier{" + "value=" + value + ", type=" + type + '}';
    }

    /**
     * Implementation of the comparator interface. This compares the type and value of
     * the identifier only.
     *
     * @param o the object being compared
     * @return an integer indicating the ordering
     */
    @Override
    public int compareTo(Identifier o) {
        if (o == null) {
            throw new IllegalArgumentException("Unable to compare a null identifier");
        }
        return new CompareToBuilder()
                .append(this.type, o.type)
                .append(this.value, o.value)
                .toComparison();
    }
}
