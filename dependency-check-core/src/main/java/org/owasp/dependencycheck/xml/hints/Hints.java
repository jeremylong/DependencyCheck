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

import java.util.List;

/**
 * A collection of hint rules.
 *
 * @author Jeremy Long
 */
public class Hints {

    /**
     * The list of hint rules.
     */
    private List<HintRule> hintRules;

    /**
     * The duplicating hint rules.
     */
    private List<VendorDuplicatingHintRule> vendorDuplicatingHintRules;

    /**
     * Get the value of hintRules.
     *
     * @return the value of hintRules
     */
    public List<HintRule> getHintRules() {
        return hintRules;
    }

    /**
     * Set the value of hintRules.
     *
     * @param hintRules new value of hintRules
     */
    public void setHintRules(List<HintRule> hintRules) {
        this.hintRules = hintRules;
    }

    /**
     * Get the value of vendorDuplicatingHintRules.
     *
     * @return the value of vendorDuplicatingHintRules
     */
    public List<VendorDuplicatingHintRule> getVendorDuplicatingHintRules() {
        return vendorDuplicatingHintRules;
    }

    /**
     * Set the value of vendorDuplicatingHintRules.
     *
     * @param vendorDuplicatingHintRules new value of vendorDuplicatingHintRules
     */
    public void setVendorDuplicatingHintRules(List<VendorDuplicatingHintRule> vendorDuplicatingHintRules) {
        this.vendorDuplicatingHintRules = vendorDuplicatingHintRules;
    }
}
