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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.suppression;

import java.util.regex.Pattern;

/**
 * A simple PropertyType used to represent a string value that could be used as
 * a regular expression or could be case insensitive. The equals method has been
 * over-ridden so that the object will correctly compare to strings.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class PropertyType {

    //<editor-fold defaultstate="collapsed" desc="properties">
    /**
     * The value.
     */
    private String value;

    /**
     * Gets the value of the value property.
     *
     * @return the value of the value property
     *
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
     * Whether or not the expression is a regex.
     */
    private boolean regex = false;

    /**
     * Returns whether or not the value is a regex.
     *
     * @return true if the value is a regex, otherwise false
     *
     */
    public boolean isRegex() {
        return regex;
    }

    /**
     * Sets whether the value property is a regex.
     *
     * @param value true if the value is a regex, otherwise false
     *
     */
    public void setRegex(boolean value) {
        this.regex = value;
    }
    /**
     * Indicates case sensitivity.
     */
    private boolean caseSensitive = false;

    /**
     * Gets the value of the caseSensitive property.
     *
     * @return true if the value is case sensitive
     *
     */
    public boolean isCaseSensitive() {
        return caseSensitive;
    }

    /**
     * Sets the value of the caseSensitive property.
     *
     * @param value whether the value is case sensitive
     *
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
            Pattern rx;
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
        int hash = 3;
        hash = 59 * hash + (this.value != null ? this.value.hashCode() : 0);
        hash = 59 * hash + (this.regex ? 1 : 0);
        hash = 59 * hash + (this.caseSensitive ? 1 : 0);
        return hash;
    }

    /**
     * Default implementation of equals.
     *
     * @param obj the object to compare
     * @return whether the objects are equivalent
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final PropertyType other = (PropertyType) obj;
        if ((this.value == null) ? (other.value != null) : !this.value.equals(other.value)) {
            return false;
        }
        if (this.regex != other.regex) {
            return false;
        }
        if (this.caseSensitive != other.caseSensitive) {
            return false;
        }
        return true;
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
