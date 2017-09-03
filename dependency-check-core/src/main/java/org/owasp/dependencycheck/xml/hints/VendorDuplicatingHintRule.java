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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.hints;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Used to duplicate vendor evidence within a collection. The intent is if any
 * evidence is found in a collection that matches the value given the evidence
 * will be duplicated and the value replaced with the value indicated.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class VendorDuplicatingHintRule {

    /**
     * The evidence value to duplicate if found.
     */
    private String value;

    /**
     * The value to replace when duplicating the evidence.
     */
    private String duplicate;

    /**
     * Constructs a new duplicating rule.
     *
     * @param value the value to duplicate the evidence if found
     * @param duplicate the value to replace within the duplicated evidence
     */
    public VendorDuplicatingHintRule(String value, String duplicate) {
        this.value = value;
        this.duplicate = duplicate;
    }

    /**
     * Get the value of value.
     *
     * @return the value of value
     */
    public String getValue() {
        return value;
    }

    /**
     * Set the value of value.
     *
     * @param value new value of value
     */
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * Get the value of duplicate.
     *
     * @return the value of duplicate
     */
    public String getDuplicate() {
        return duplicate;
    }

    /**
     * Set the value of duplicate.
     *
     * @param duplicate new value of duplicate
     */
    public void setDuplicate(String duplicate) {
        this.duplicate = duplicate;
    }
}
