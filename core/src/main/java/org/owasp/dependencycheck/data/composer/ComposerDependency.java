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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.composer;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Represents a dependency (GAV, right now) from a Composer dependency.
 *
 * @author colezlaw
 */
@ThreadSafe
public final class ComposerDependency {

    /**
     * The group
     */
    private final String group;

    /**
     * The project
     */
    private final String project;

    /**
     * The version
     */
    private final String version;

    /**
     * Create a ComposerDependency from group, project, and version.
     *
     * @param group the group
     * @param project the project
     * @param version the version
     */
    public ComposerDependency(String group, String project, String version) {
        this.group = group;
        this.project = project;
        this.version = version;
    }

    /**
     * Get the group.
     *
     * @return the group
     */
    public String getGroup() {
        return group;
    }

    /**
     * Get the project.
     *
     * @return the project
     */
    public String getProject() {
        return project;
    }

    /**
     * Get the version.
     *
     * @return the version
     */
    public String getVersion() {
        return version;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ComposerDependency)) {
            return false;
        }

        final ComposerDependency that = (ComposerDependency) o;

        if (group != null ? !group.equals(that.group) : that.group != null) {
            return false;
        }
        if (project != null ? !project.equals(that.project) : that.project != null) {
            return false;
        }
        return !(version != null ? !version.equals(that.version) : that.version != null);

    }

    @Override
    public int hashCode() {
        int result = group != null ? group.hashCode() : 0;
        result = 31 * result + (project != null ? project.hashCode() : 0);
        result = 31 * result + (version != null ? version.hashCode() : 0);
        return result;
    }
}
