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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nuget;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Represents the contents of a Nuspec manifest.
 *
 * @author colezlaw
 */
@ThreadSafe
public class NugetPackage extends NugetPackageReference {

    /**
     * The title.
     */
    private String title;

    /**
     * The authors.
     */
    private String authors;

    /**
     * The owners.
     */
    private String owners;

    /**
     * The licenseUrl.
     */
    private String licenseUrl;

    /**
     * The description.
     */
    private String description;

    /**
     * Sets the title.
     *
     * @param title the title
     */
    public void setTitle(String title) {
        this.title = title;
    }

    /**
     * Gets the title.
     *
     * @return the title
     */
    public String getTitle() {
        return title;
    }

    /**
     * Sets the authors.
     *
     * @param authors the authors
     */
    public void setAuthors(String authors) {
        this.authors = authors;
    }

    /**
     * Gets the authors.
     *
     * @return the authors
     */
    public String getAuthors() {
        return authors;
    }

    /**
     * Sets the owners.
     *
     * @param owners the owners
     */
    public void setOwners(String owners) {
        this.owners = owners;
    }

    /**
     * Gets the owners.
     *
     * @return the owners
     */
    public String getOwners() {
        return owners;
    }

    /**
     * Sets the licenseUrl.
     *
     * @param licenseUrl the licenseUrl
     */
    public void setLicenseUrl(String licenseUrl) {
        this.licenseUrl = licenseUrl;
    }

    /**
     * Gets the licenseUrl.
     *
     * @return the licenseUrl
     */
    public String getLicenseUrl() {
        return licenseUrl;
    }

    /**
     * Gets the description.
     *
     * @return the description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the description.
     *
     * @param description the description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof NugetPackage)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final NugetPackage rhs = (NugetPackage) obj;
        return new EqualsBuilder()
                .appendSuper(super.equals(obj))
                .append(title, rhs.title)
                .append(authors, rhs.authors)
                .append(owners, rhs.owners)
                .append(licenseUrl, rhs.licenseUrl)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(33, 87)
                .append(title)
                .append(authors)
                .append(owners)
                .append(licenseUrl)
                .toHashCode();
    }

}
