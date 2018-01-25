/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2017 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.taskdefs;

/**
 * Class : {@link SuppressionFile} Responsibility : Models a suppression file
 * nested XML element where the simple content is its location.
 *
 * @author Phillip Whittlesea
 */
public class SuppressionFile {

    /**
     * The path to the suppression file.
     */
    private String path;

    /**
     * Sets the path to the suppression file.
     *
     * @param path the path to the suppression file
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     * Gets the path to the suppression file.
     *
     * @return the path
     */
    public String getPath() {
        return path;
    }

}
