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
 * Copyright (c) 2022 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.pom;

import java.io.Serializable;
import java.util.Objects;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Represents the developer node within the pom.xml.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class Developer implements Serializable {

    /**
     * Generated UUID.
     */
    private static final long serialVersionUID = 7016253914202775026L;

    /**
     * The id of the developer.
     */
    private String id;
    /**
     * The developers name.
     */
    private String name;
    /**
     * The developers email.
     */
    private String email;
    /**
     * The developer's organization.
     */
    private String organization;
    /**
     * The developer's organization URL.
     */
    private String organizationUrl;

    /**
     * Get the value of id.
     *
     * @return the value of id
     */
    public String getId() {
        return id;
    }

    /**
     * Set the value of id.
     *
     * @param id new value of id
     */
    public void setId(String id) {
        this.id = id;
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
     * Get the value of email.
     *
     * @return the value of email
     */
    public String getEmail() {
        return email;
    }

    /**
     * Set the value of email.
     *
     * @param email new value of email
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * Get the value of organization.
     *
     * @return the value of organization
     */
    public String getOrganization() {
        return organization;
    }

    /**
     * Set the value of organization.
     *
     * @param organization new value of organization
     */
    public void setOrganization(String organization) {
        this.organization = organization;
    }

    /**
     * Get the value of organizationUrl.
     *
     * @return the value of organizationUrl
     */
    public String getOrganizationUrl() {
        return organizationUrl;
    }

    /**
     * Set the value of organizationUrl.
     *
     * @param organizationUrl new value of organizationUrl
     */
    public void setOrganizationUrl(String organizationUrl) {
        this.organizationUrl = organizationUrl;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 61 * hash + Objects.hashCode(this.id);
        hash = 61 * hash + Objects.hashCode(this.name);
        hash = 61 * hash + Objects.hashCode(this.email);
        hash = 61 * hash + Objects.hashCode(this.organization);
        hash = 61 * hash + Objects.hashCode(this.organizationUrl);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Developer other = (Developer) obj;
        if (!Objects.equals(this.id, other.id)) {
            return false;
        }
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        if (!Objects.equals(this.email, other.email)) {
            return false;
        }
        if (!Objects.equals(this.organization, other.organization)) {
            return false;
        }
        if (!Objects.equals(this.organizationUrl, other.organizationUrl)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "Developer{"
                + "id=" + id
                + ", name=" + name
                + ", email=" + email
                + ", organization=" + organization
                + ", organizationUrl=" + organizationUrl + '}';
    }

}
