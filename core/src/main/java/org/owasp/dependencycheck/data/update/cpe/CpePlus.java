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
package org.owasp.dependencycheck.data.update.cpe;

import javax.annotation.concurrent.ThreadSafe;
import us.springett.parsers.cpe.Cpe;

/**
 * A simple wrapper object that allows one to carry the ecosystem along with the
 * CPE.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class CpePlus {

    /**
     * The CPE object.
     */
    private Cpe cpe;
    /**
     * The ecosystem that to which the CPE belongs.
     */
    private String ecosystem;

    /**
     * Construct a new CPE plus object.
     *
     * @param cpe the CPE
     * @param ecosystem the ecosystem
     */
    public CpePlus(Cpe cpe, String ecosystem) {
        this.cpe = cpe;
        this.ecosystem = ecosystem;
    }

    /**
     * Get the value of ecosystem.
     *
     * @return the value of ecosystem
     */
    public String getEcosystem() {
        return ecosystem;
    }

    /**
     * Set the value of ecosystem.
     *
     * @param ecosystem new value of ecosystem
     */
    public void setEcosystem(String ecosystem) {
        this.ecosystem = ecosystem;
    }

    /**
     * Get the value of CPE.
     *
     * @return the value of CPE
     */
    public Cpe getCpe() {
        return cpe;
    }

    /**
     * Set the value of CPE.
     *
     * @param cpe new value of CPE
     */
    public void setCpe(Cpe cpe) {
        this.cpe = cpe;
    }

}
