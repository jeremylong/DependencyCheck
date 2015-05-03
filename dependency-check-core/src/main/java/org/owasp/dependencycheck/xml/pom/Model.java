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

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * A simple pojo to hold data related to a Maven POM file.
 *
 * @author jeremy
 */
public class Model {

    /**
     * The name of the project.
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
     * The organization name.
     */
    private String organization;

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
     * The description.
     */
    private String description;

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
     * The group id.
     */
    private String groupId;

    /**
     * Get the value of groupId.
     *
     * @return the value of groupId
     */
    public String getGroupId() {
        return groupId;
    }

    /**
     * Set the value of groupId.
     *
     * @param groupId new value of groupId
     */
    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    /**
     * The artifact id.
     */
    private String artifactId;

    /**
     * Get the value of artifactId.
     *
     * @return the value of artifactId
     */
    public String getArtifactId() {
        return artifactId;
    }

    /**
     * Set the value of artifactId.
     *
     * @param artifactId new value of artifactId
     */
    public void setArtifactId(String artifactId) {
        this.artifactId = artifactId;
    }

    /**
     * The version number.
     */
    private String version;

    /**
     * Get the value of version.
     *
     * @return the value of version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Set the value of version.
     *
     * @param version new value of version
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * The parent group id.
     */
    private String parentGroupId;

    /**
     * Get the value of parentGroupId.
     *
     * @return the value of parentGroupId
     */
    public String getParentGroupId() {
        return parentGroupId;
    }

    /**
     * Set the value of parentGroupId.
     *
     * @param parentGroupId new value of parentGroupId
     */
    public void setParentGroupId(String parentGroupId) {
        this.parentGroupId = parentGroupId;
    }

    /**
     * The parent artifact id.
     */
    private String parentArtifactId;

    /**
     * Get the value of parentArtifactId.
     *
     * @return the value of parentArtifactId
     */
    public String getParentArtifactId() {
        return parentArtifactId;
    }

    /**
     * Set the value of parentArtifactId.
     *
     * @param parentArtifactId new value of parentArtifactId
     */
    public void setParentArtifactId(String parentArtifactId) {
        this.parentArtifactId = parentArtifactId;
    }

    /**
     * The parent version number.
     */
    private String parentVersion;

    /**
     * Get the value of parentVersion.
     *
     * @return the value of parentVersion
     */
    public String getParentVersion() {
        return parentVersion;
    }

    /**
     * Set the value of parentVersion.
     *
     * @param parentVersion new value of parentVersion
     */
    public void setParentVersion(String parentVersion) {
        this.parentVersion = parentVersion;
    }

    /**
     * The list of licenses.
     */
    private List<License> licenses = new ArrayList<License>();

    /**
     * Returns the list of licenses.
     *
     * @return the list of licenses
     */
    public List<License> getLicenses() {
        return licenses;
    }

    /**
     * Adds a new license to the list of licenses.
     *
     * @param license the license to add
     */
    public void addLicense(License license) {
        licenses.add(license);
    }

    /**
     * Process the Maven properties file and interpolate all properties.
     *
     * @param properties new value of properties
     */
    public void processProperties(Properties properties) {
        this.groupId = interpolateString(this.groupId, properties);
        this.artifactId = interpolateString(this.artifactId, properties);
        this.version = interpolateString(this.version, properties);
        this.description = interpolateString(this.description, properties);
        for (License l : this.getLicenses()) {
            l.setName(interpolateString(l.getName(), properties));
            l.setUrl(interpolateString(l.getUrl(), properties));
        }
        this.name = interpolateString(this.name, properties);
        this.organization = interpolateString(this.organization, properties);
        this.parentGroupId = interpolateString(this.parentGroupId, properties);
        this.parentArtifactId = interpolateString(this.parentArtifactId, properties);
        this.parentVersion = interpolateString(this.parentVersion, properties);

    }

    /**
     * <p>
     * A utility function that will interpolate strings based on values given in the properties file. It will also interpolate the
     * strings contained within the properties file so that properties can reference other properties.</p>
     * <p>
     * <b>Note:</b> if there is no property found the reference will be removed. In other words, if the interpolated string will
     * be replaced with an empty string.
     * </p>
     * <p>
     * Example:</p>
     * <code>
     * Properties p = new Properties();
     * p.setProperty("key", "value");
     * String s = interpolateString("'${key}' and '${nothing}'", p);
     * System.out.println(s);
     * </code>
     * <p>
     * Will result in:</p>
     * <code>
     * 'value' and ''
     * </code>
     *
     * @param text the string that contains references to properties.
     * @param properties a collection of properties that may be referenced within the text.
     * @return the interpolated text.
     */
    public static String interpolateString(String text, Properties properties) {
        final Properties props = properties;
        if (text == null) {
            return text;
        }
        if (props == null) {
            return text;
        }

        final int pos = text.indexOf("${");
        if (pos < 0) {
            return text;
        }
        final int end = text.indexOf("}");
        if (end < pos) {
            return text;
        }

        final String propName = text.substring(pos + 2, end);
        String propValue = interpolateString(props.getProperty(propName), props);
        if (propValue == null) {
            propValue = "";
        }
        final StringBuilder sb = new StringBuilder(propValue.length() + text.length());
        sb.append(text.subSequence(0, pos));
        sb.append(propValue);
        sb.append(text.substring(end + 1));
        return interpolateString(sb.toString(), props); //yes yes, this should be a loop...
    }

}
