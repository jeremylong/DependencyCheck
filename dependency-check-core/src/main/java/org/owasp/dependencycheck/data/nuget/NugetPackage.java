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

import javax.annotation.concurrent.ThreadSafe;

/**
 * Represents the contents of a Nuspec manifest.
 *
 * @author colezlaw
 */
@ThreadSafe
public class NugetPackage {

    /**
     * The id.
     */
    private String id;

    /**
     * The version.
     */
    private String version;

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
     * Sets the id.
     *
     * @param id the id
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Gets the id.
     *
     * @return the id
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the version.
     *
     * @param version the version
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Gets the version.
     *
     * @return the version
     */
    public String getVersion() {
        return version;
    }

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

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || other.getClass() != this.getClass()) {
            return false;
        }
        final NugetPackage o = (NugetPackage) other;
        return o.getId().equals(id)
                && o.getVersion().equals(version)
                && o.getTitle().equals(title)
                && o.getAuthors().equals(authors)
                && o.getOwners().equals(owners)
                && o.getLicenseUrl().equals(licenseUrl);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 31 * hash + (null == id ? 0 : id.hashCode());
        hash = 31 * hash + (null == version ? 0 : version.hashCode());
        hash = 31 * hash + (null == title ? 0 : title.hashCode());
        hash = 31 * hash + (null == authors ? 0 : authors.hashCode());
        hash = 31 * hash + (null == owners ? 0 : owners.hashCode());
        hash = 31 * hash + (null == licenseUrl ? 0 : licenseUrl.hashCode());
        return hash;
    }
}
