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

import javax.annotation.concurrent.ThreadSafe;

/**
 *
 * @author jeremy
 */
@ThreadSafe
public class License {

    /**
     * The url to the license.
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
     * @param url the license url
     */
    public License(String name, String url) {
        this.url = url;
        this.name = name;

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
        int hash = 7;
        hash = 89 * hash + (this.url != null ? this.url.hashCode() : 0);
        hash = 89 * hash + (this.name != null ? this.name.hashCode() : 0);
        return hash;
    }

    /**
     * Generated equals method to perform equality check.
     *
     * @param obj the object to check
     * @return true if the objects are equal; otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final License other = (License) obj;
        if ((this.url == null) ? (other.url != null) : !this.url.equals(other.url)) {
            return false;
        }
        return !((this.name == null) ? (other.name != null) : !this.name.equals(other.name));
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
