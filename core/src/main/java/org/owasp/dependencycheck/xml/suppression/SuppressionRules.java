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
package org.owasp.dependencycheck.xml.suppression;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
public class SuppressionRules {

    /**
     * Singleton.
     */
    private static final SuppressionRules INSTANCE = new SuppressionRules();
    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionRules.class);
    /**
     * The list of suppression rules.
     */
    private static final List<SuppressionRule> rules = new ArrayList<>();

    private SuppressionRules() {
    }

    /**
     * Returns the instance of SuppressionRules.
     *
     * @return the instance of SuppressionRules
     */
    public static SuppressionRules getInstance() {
        return INSTANCE;
    }

    /**
     * Get the number of suppression rules.
     *
     * @return the number of suppression rules
     */
    public int size() {
        return rules.size();
    }

    /**
     * Returns true if there are no suppression rules; otherwise false.
     *
     * @return true if there are no suppression rules; otherwise false
     */
    public boolean isEmpty() {
        return rules.isEmpty();
    }

    /**
     * Returns the list of suppression rules.
     *
     * @return the list of suppression rules
     */
    public List<SuppressionRule> list() {
        return rules;
    }

    /**
     * Appends the new suppression rules to the list of rules.
     *
     * @param newRules the new suppression rules
     */
    public void addAll(List<SuppressionRule> newRules) {
        rules.addAll(newRules);
    }

    /**
     * Logs unused suppression rules.
     */
    public void logUnusedRules() {
        rules.forEach((rule) -> {
            if (!rule.isMatched() && !rule.isBase()) {
                LOGGER.debug("Suppression Rule had zero matches: {}", rule.toString());
            }
        });
    }
}
