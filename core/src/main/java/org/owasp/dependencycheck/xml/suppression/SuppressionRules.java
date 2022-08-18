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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
public final class SuppressionRules {

    /**
     * Singleton.
     */
    private static final SuppressionRules INSTANCE = new SuppressionRules();
    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionRules.class);
    /**
     * The list of suppression RULES.
     */
    private static final List<SuppressionRule> RULES = new ArrayList<>();

    private SuppressionRules() {
    }

    /**
     * Returns the instance of SuppressionRules.
     *
     * @return the instance of SuppressionRules
     */
    @SuppressFBWarnings(justification = "Intended", value = {"MS_EXPOSE_REP"})
    public static SuppressionRules getInstance() {
        return INSTANCE;
    }

    /**
     * Get the number of suppression RULES.
     *
     * @return the number of suppression RULES
     */
    public int size() {
        return RULES.size();
    }

    /**
     * Returns true if there are no suppression RULES; otherwise false.
     *
     * @return true if there are no suppression RULES; otherwise false
     */
    public boolean isEmpty() {
        return RULES.isEmpty();
    }

    /**
     * Returns the list of suppression RULES.
     *
     * @return the list of suppression RULES
     */
    public List<SuppressionRule> list() {
        return RULES;
    }

    /**
     * Appends the new suppression RULES to the list of RULES.
     *
     * @param newRules the new suppression RULES
     */
    public void addAll(List<SuppressionRule> newRules) {
        RULES.addAll(newRules);
    }

    /**
     * Logs unused suppression RULES.
     */
    public void logUnusedRules() {
        RULES.forEach((rule) -> {
            if (!rule.isMatched() && !rule.isBase()) {
                LOGGER.debug("Suppression Rule had zero matches: {}", rule.toString());
            }
        });
    }
}
