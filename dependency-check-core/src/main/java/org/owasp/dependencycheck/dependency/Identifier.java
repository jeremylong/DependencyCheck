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

/**
 * In identifier such as a CPE or dependency coordinates (i.e. GAV).
 *
 * @author Jeremy Long
 */
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
     * The url for the identifier.
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
     * @param url the identifier url.
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
     * @param url the identifier url.
     * @param description the description of the identifier.
     */
    public Identifier(String type, String value, String url, String description) {
        this(type, value, url);
        this.description = description;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Identifier other = (Identifier) obj;
        if ((this.value == null) ? (other.value != null) : !this.value.equals(other.value)) {
            return false;
        }
        return !((this.type == null) ? (other.type != null) : !this.type.equals(other.type));
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + (this.value != null ? this.value.hashCode() : 0);
        hash = 53 * hash + (this.type != null ? this.type.hashCode() : 0);
        return hash;
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
     * Implementation of the comparator interface. This compares the value of
     * the identifier only.
     *
     * @param o the object being compared
     * @return an integer indicating the ordering
     */
    @Override
    public int compareTo(Identifier o) {
        if (o == null) {
            return -1;
        }
        return this.value.compareTo(o.value);
    }
}
