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

import java.io.Serializable;

/**
 * An external reference for a vulnerability. This contains a name, URL, and a
 * source.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class Reference implements Serializable, Comparable<Reference> {

    /**
     * the serial version uid.
     */
    private static final long serialVersionUID = -3444464824563008021L;
    /**
     * The name of the reference.
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
     * the url for the reference.
     */
    private String url;

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
     * the source of the reference.
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

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Reference other = (Reference) obj;
        if ((this.name == null) ? (other.name != null) : !this.name.equals(other.name)) {
            return false;
        }
        if ((this.url == null) ? (other.url != null) : !this.url.equals(other.url)) {
            return false;
        }
        if ((this.source == null) ? (other.source != null) : !this.source.equals(other.source)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 67 * hash + (this.name != null ? this.name.hashCode() : 0);
        hash = 67 * hash + (this.url != null ? this.url.hashCode() : 0);
        hash = 67 * hash + (this.source != null ? this.source.hashCode() : 0);
        return hash;
    }

    /**
     * Implementation of the comparable interface.
     *
     * @param o the Reference being compared
     * @return an integer indicating the ordering of the two objects
     */
    public int compareTo(Reference o) {
        if (source.equals(o.source)) {
            if (name.equals(o.name)) {
                if (url.equals(o.url)) {
                    return 0; //they are equal
                } else {
                    return url.compareTo(o.url);
                }
            } else {
                return name.compareTo(o.name);
            }
        } else {
            return source.compareTo(o.source);
        }
    }
}
