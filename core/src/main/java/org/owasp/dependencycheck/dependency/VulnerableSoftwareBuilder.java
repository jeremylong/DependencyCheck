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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.dependency;

import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;
import us.springett.parsers.cpe.values.LogicalValue;
import us.springett.parsers.cpe.values.Part;

/**
 * A builder for VulnerableSoftware objects.
 *
 * @author Jeremy Long
 */
public class VulnerableSoftwareBuilder extends CpeBuilder {

    /**
     * The ending range, excluding the specified version, for matching
     * vulnerable software
     */
    private String versionEndExcluding = null;
    /**
     * The ending range, including the specified version, for matching
     * vulnerable software
     */
    private String versionEndIncluding = null;
    /**
     * The starting range, excluding the specified version, for matching
     * vulnerable software
     */
    private String versionStartExcluding = null;
    /**
     * the starting range, including the specified version, for matching
     * vulnerable software
     */
    private String versionStartIncluding = null;
    /**
     * A flag indicating whether this represents a vulnerable software object.
     */
    private boolean vulnerable = true;

    /**
     * Builds the CPE Object.
     *
     * @return the CPE Object
     * @throws CpeValidationException thrown if one of the CPE components is
     * invalid
     */
    @Override
    public VulnerableSoftware build() throws CpeValidationException {
        final VulnerableSoftware vs = new VulnerableSoftware(getPart(), getVendor(), getProduct(),
                getVersion(), getUpdate(), getEdition(),
                getLanguage(), getSwEdition(), getTargetSw(), getTargetHw(), getOther(),
                versionEndExcluding, versionEndIncluding, versionStartExcluding,
                versionStartIncluding, vulnerable);
        reset();
        return vs;
    }

    /**
     * Resets the Vulnerable Software Builder to a clean state.
     */
    @Override
    protected void reset() {
        super.reset();
        versionEndExcluding = null;
        versionEndIncluding = null;
        versionStartExcluding = null;
        versionStartIncluding = null;
        vulnerable = true;
    }

    /**
     * Adds a base CPE object to build a vulnerable software object from.
     *
     * @param cpe the base CPE
     * @return a reference to the builder
     */
    public VulnerableSoftwareBuilder cpe(Cpe cpe) {
        this.part(cpe.getPart()).wfVendor(cpe.getWellFormedVendor()).wfProduct(cpe.getWellFormedProduct())
                .wfVersion(cpe.getWellFormedVersion()).wfUpdate(cpe.getWellFormedUpdate())
                .wfEdition(cpe.getWellFormedEdition()).wfLanguage(cpe.getWellFormedLanguage())
                .wfSwEdition(cpe.getWellFormedSwEdition()).wfTargetSw(cpe.getWellFormedTargetSw())
                .wfTargetHw(cpe.getWellFormedTargetHw()).wfOther(cpe.getWellFormedOther());
        return this;
    }

    /**
     * The ending range, excluding the specified version, for matching
     * vulnerable software.
     *
     * @param versionEndExcluding the version range
     * @return a reference to the builder
     */
    public VulnerableSoftwareBuilder versionEndExcluding(String versionEndExcluding) {
        this.versionEndExcluding = versionEndExcluding;
        return this;
    }

    /**
     * The ending range, including the specified version, for matching
     * vulnerable software.
     *
     * @param versionEndIncluding the version range
     * @return a reference to the builder
     */
    public VulnerableSoftwareBuilder versionEndIncluding(String versionEndIncluding) {
        this.versionEndIncluding = versionEndIncluding;
        return this;
    }

    /**
     * The starting range, excluding the specified version, for matching
     * vulnerable software.
     *
     * @param versionStartExcluding the version range
     * @return a reference to the builder
     */
    public VulnerableSoftwareBuilder versionStartExcluding(String versionStartExcluding) {
        this.versionStartExcluding = versionStartExcluding;
        return this;
    }

    /**
     * The starting range, including the specified version, for matching
     * vulnerable software.
     *
     * @param versionStartIncluding the version range
     * @return a reference to the builder
     */
    public VulnerableSoftwareBuilder versionStartIncluding(String versionStartIncluding) {
        this.versionStartIncluding = versionStartIncluding;
        return this;
    }

    /**
     * A flag indicating whether this represents a vulnerable software object.
     *
     * @param vulnerable whether or not this VulnerableSoftware object
     * represents an actually vulnerable package
     * @return a reference to the builder
     */
    public VulnerableSoftwareBuilder vulnerable(boolean vulnerable) {
        this.vulnerable = vulnerable;
        return this;
    }

    //<editor-fold defaultstate="collapsed" desc="Overrides for builder functions from parent so that the correct type can be returned">
    @Override
    public VulnerableSoftwareBuilder wfOther(String other) {
        return (VulnerableSoftwareBuilder) super.wfOther(other); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder wfTargetHw(String targetHw) {
        return (VulnerableSoftwareBuilder) super.wfTargetHw(targetHw); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder wfTargetSw(String targetSw) {
        return (VulnerableSoftwareBuilder) super.wfTargetSw(targetSw); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder wfSwEdition(String swEdition) {
        return (VulnerableSoftwareBuilder) super.wfSwEdition(swEdition); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder wfLanguage(String language) {
        return (VulnerableSoftwareBuilder) super.wfLanguage(language); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder wfEdition(String edition) {
        return (VulnerableSoftwareBuilder) super.wfEdition(edition); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder wfUpdate(String update) {
        return (VulnerableSoftwareBuilder) super.wfUpdate(update); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder wfVersion(String version) {
        return (VulnerableSoftwareBuilder) super.wfVersion(version); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder wfProduct(String product) {
        return (VulnerableSoftwareBuilder) super.wfProduct(product); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder wfVendor(String vendor) {
        return (VulnerableSoftwareBuilder) super.wfVendor(vendor); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder other(LogicalValue other) {
        return (VulnerableSoftwareBuilder) super.other(other); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder targetHw(LogicalValue targetHw) {
        return (VulnerableSoftwareBuilder) super.targetHw(targetHw); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder targetSw(LogicalValue targetSw) {
        return (VulnerableSoftwareBuilder) super.targetSw(targetSw); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder swEdition(LogicalValue swEdition) {
        return (VulnerableSoftwareBuilder) super.swEdition(swEdition); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder language(LogicalValue language) {
        return (VulnerableSoftwareBuilder) super.language(language); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder update(LogicalValue update) {
        return (VulnerableSoftwareBuilder) super.update(update); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder version(LogicalValue version) {
        return (VulnerableSoftwareBuilder) super.version(version); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder product(LogicalValue product) {
        return (VulnerableSoftwareBuilder) super.product(product); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder vendor(LogicalValue vendor) {
        return (VulnerableSoftwareBuilder) super.vendor(vendor); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder other(String other) {
        return (VulnerableSoftwareBuilder) super.other(other); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder targetHw(String targetHw) {
        return (VulnerableSoftwareBuilder) super.targetHw(targetHw); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder targetSw(String targetSw) {
        return (VulnerableSoftwareBuilder) super.targetSw(targetSw); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder swEdition(String swEdition) {
        return (VulnerableSoftwareBuilder) super.swEdition(swEdition); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder language(String language) {
        return (VulnerableSoftwareBuilder) super.language(language); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder update(String update) {
        return (VulnerableSoftwareBuilder) super.update(update); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder version(String version) {
        return (VulnerableSoftwareBuilder) super.version(version); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder product(String product) {
        return (VulnerableSoftwareBuilder) super.product(product); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder vendor(String vendor) {
        return (VulnerableSoftwareBuilder) super.vendor(vendor); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder part(String part) throws CpeParsingException {
        return (VulnerableSoftwareBuilder) super.part(part); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder part(Part part) {
        return (VulnerableSoftwareBuilder) super.part(part); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder edition(LogicalValue edition) {
        return (VulnerableSoftwareBuilder) super.edition(edition); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VulnerableSoftwareBuilder edition(String edition) {
        return (VulnerableSoftwareBuilder) super.edition(edition); //To change body of generated methods, choose Tools | Templates.
    }
//</editor-fold>

}
