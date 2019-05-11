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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.suppression;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.regex.Pattern;
import javax.annotation.concurrent.ThreadSafe;

/**
 * A simple PropertyType used to represent a string value that could be used as
 * a regular expression or could be case insensitive. The equals method has been
 * over-ridden so that the object will correctly compare to strings.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class PropertyType {

    //<editor-fold defaultstate="collapsed" desc="properties">
    /**
     * The value.
     */
    private String value;
    /**
     * Whether or not the expression is a regex.
     */
    private boolean regex = false;
    /**
     * Indicates case sensitivity.
     */
    private boolean caseSensitive = false;

    /**
     * Gets the value of the value property.
     *
     * @return the value of the value property
     */
    public String getValue() {
        return value;
    }

    /**
     * Sets the value of the value property.
     *
     * @param value the value of the value property
     */
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * Returns whether or not the value is a regex.
     *
     * @return true if the value is a regex, otherwise false
     */
    public boolean isRegex() {
        return regex;
    }

    /**
     * Sets whether the value property is a regex.
     *
     * @param value true if the value is a regex, otherwise false
     */
    public void setRegex(boolean value) {
        this.regex = value;
    }

    /**
     * Gets the value of the caseSensitive property.
     *
     * @return true if the value is case sensitive
     */
    public boolean isCaseSensitive() {
        return caseSensitive;
    }

    /**
     * Sets the value of the caseSensitive property.
     *
     * @param value whether the value is case sensitive
     */
    public void setCaseSensitive(boolean value) {
        this.caseSensitive = value;
    }
    //</editor-fold>

    /**
     * Uses the object's properties to determine if the supplied string matches
     * the value of this property.
     *
     * @param text the String to validate
     * @return whether the text supplied is matched by the value of the property
     */
    public boolean matches(String text) {
        if (text == null) {
            return false;
        }
        if (this.regex) {
            final Pattern rx;
            if (this.caseSensitive) {
                rx = Pattern.compile(this.value);
            } else {
                rx = Pattern.compile(this.value, Pattern.CASE_INSENSITIVE);
            }
            return rx.matcher(text).matches();
        } else {
            if (this.caseSensitive) {
                return value.equals(text);
            } else {
                return value.equalsIgnoreCase(text);
            }
        }
    }

    //<editor-fold defaultstate="collapsed" desc="standard implementations of hashCode, equals, and toString">

    /**
     * Default implementation of hashCode.
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(3, 59)
                .append(value)
                .append(regex)
                .append(caseSensitive)
                .toHashCode();
    }

    /**
     * Default implementation of equals.
     *
     * @param obj the object to compare
     * @return whether the objects are equivalent
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof PropertyType)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final PropertyType rhs = (PropertyType) obj;
        return new EqualsBuilder()
                .append(value, rhs.value)
                .append(regex, rhs.regex)
                .append(caseSensitive, rhs.caseSensitive)
                .isEquals();
    }

    /**
     * Default implementation of toString().
     *
     * @return the string representation of the object
     */
    @Override
    public String toString() {
        return "PropertyType{" + "value=" + value + ", regex=" + regex + ", caseSensitive=" + caseSensitive + '}';
    }
    //</editor-fold>
}
