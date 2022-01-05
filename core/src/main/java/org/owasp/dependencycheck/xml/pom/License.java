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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.pom;

import java.io.Serializable;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import javax.annotation.concurrent.ThreadSafe;

/**
 *
 * @author jeremy long
 */
@ThreadSafe
public class License implements Serializable {

    /**
     * Generated UUID.
     */
    private static final long serialVersionUID = 7009115254312746992L;

    /**
     * The URL to the license.
     */
    private String url;
    /**
     * The name of the license.
     */
    private String name;

    /**
     * Constructs a new license object.
     */
    public License() {
    }

    /**
     * Constructs a new license.
     *
     * @param name the name of the license
     * @param url the license URL
     */
    public License(String name, String url) {
        this.url = url;
        this.name = name;

    }

    /**
     * Get the value of URL.
     *
     * @return the value of URL
     */
    public String getUrl() {
        return url;
    }

    /**
     * Set the value of URL.
     *
     * @param url new value of URL
     */
    public void setUrl(String url) {
        this.url = url;
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
     * Generated hashCode implementation.
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(13, 49)
                .append(name)
                .append(url)
                .toHashCode();
    }

    /**
     * Generated equals method to perform equality check.
     *
     * @param obj the object to check
     * @return true if the objects are equal; otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof License)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final License rhs = (License) obj;
        return new EqualsBuilder()
                .append(name, rhs.name)
                .append(url, rhs.url)
                .isEquals();
    }

    /**
     * Generated toString.
     *
     * @return the string representation of the license
     */
    @Override
    public String toString() {
        return "License{" + "url=" + url + ", name=" + name + '}';
    }

}
