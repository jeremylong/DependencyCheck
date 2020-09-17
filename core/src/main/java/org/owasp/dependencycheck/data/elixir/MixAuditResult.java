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
 * Copyright (c) 2020 OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.elixir;

import java.util.List;

/**
 * Represents a single vulnerability result from `mix_audit --format json`.
 *
 * @author defsprite
 */
public class MixAuditResult {

    /**
     * The vulnerability id.
     */
    private final String id;
    /**
     * The CVE ID.
     */
    private final String cve;
    /**
     * The vulnerability title.
     */
    private final String title;
    /**
     * The vulnerability description.
     */
    private final String description;
    /**
     * The vulnerability disclosure date.
     */
    private final String disclosureDate;
    /**
     * The link to the vulnerability details.
     */
    private final String url;
    /**
     * The list of patched versions.
     */
    private final List<String> patchedVersions;

    /**
     * The path to the lock file.
     */
    private final String dependencyLockfile;
    /**
     * The dependency package name.
     */
    private final String dependencyPackage;
    /**
     * The dependency version.
     */
    private final String dependencyVersion;

    //CSOFF: ParameterNumber
    /**
     * Constructs a new Mix Audit Result.
     *
     * @param id the vulnerability id
     * @param cve the CVE entry name
     * @param title the CVE title
     * @param description the description of the vulnerability
     * @param disclosureDate the vulnerability disclosure date
     * @param url a link to the vulnerability information
     * @param patchedVersions the list of patched versions
     * @param dependencyLockfile the path to the lock file
     * @param dependencyPackage the name of the dependency
     * @param dependencyVersion the version of the dependency
     */
    public MixAuditResult(String id, String cve, String title, String description, String disclosureDate,
            String url, List<String> patchedVersions, String dependencyLockfile, String dependencyPackage,
            String dependencyVersion) {
        this.id = id;
        this.cve = cve;
        this.title = title;
        this.description = description;
        this.disclosureDate = disclosureDate;
        this.url = url;
        this.patchedVersions = patchedVersions;
        this.dependencyLockfile = dependencyLockfile;
        this.dependencyPackage = dependencyPackage;
        this.dependencyVersion = dependencyVersion;
    }
    //CSON: ParameterNumber

    /**
     * Returns the vulnerability id.
     *
     * @return the vulnerability id
     */
    public String getId() {
        return id;
    }

    /**
     * Returns the CVE entry name.
     *
     * @return the CVE entry name
     */
    public String getCve() {
        return cve;
    }

    /**
     * Returns the vulnerability title.
     *
     * @return the vulnerability title
     */
    public String getTitle() {
        return title;
    }

    /**
     * Returns the vulnerability description.
     *
     * @return the vulnerability description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Returns the vulnerability disclosure date.
     *
     * @return the vulnerability disclosure date
     */
    public String getDisclosureDate() {
        return disclosureDate;
    }

    /**
     * Returns the URL to the vulnerability page.
     *
     * @return the URL to the vulnerability page
     */
    public String getUrl() {
        return url;
    }

    /**
     * Returns the list of patched versions.
     *
     * @return the list of patched versions
     */
    public List<String> getPatchedVersions() {
        return patchedVersions;
    }

    /**
     * Returns the path to the dependency lock file.
     *
     * @return the path to the dependency lock file
     */
    public String getDependencyLockfile() {
        return dependencyLockfile;
    }

    /**
     * Returns the package name.
     *
     * @return the package name
     */
    public String getDependencyPackage() {
        return dependencyPackage;
    }

    /**
     * Returns the dependency version.
     *
     * @return the dependency version
     */
    public String getDependencyVersion() {
        return dependencyVersion;
    }
}
