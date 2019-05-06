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

import java.util.ArrayList;
import java.util.List;
import javax.annotation.concurrent.NotThreadSafe;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.xml.suppression.PropertyType;

/**
 * A collection of product and vendor evidence to match; if any evidence is
 * matched the addVendor and addProduct evidence should be added to the
 * dependency.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class HintRule {

    /**
     * The list of file names to match.
     */
    private final List<PropertyType> fileNames = new ArrayList<>();
    /**
     * The list of vendor evidence that is being matched.
     */
    private final List<EvidenceMatcher> givenVendor = new ArrayList<>();
    /**
     * The list of product evidence that is being matched.
     */
    private final List<EvidenceMatcher> givenProduct = new ArrayList<>();
    /**
     * The list of product evidence that is being matched.
     */
    private final List<EvidenceMatcher> givenVersion = new ArrayList<>();
    /**
     * The list of vendor hints to add.
     */
    private final List<Evidence> addVendor = new ArrayList<>();
    /**
     * The list of product evidence to add.
     */
    private final List<Evidence> addProduct = new ArrayList<>();
    /**
     * The list of version evidence to add.
     */
    private final List<Evidence> addVersion = new ArrayList<>();

    /**
     * The list of vendor hints to remove.
     */
    private final List<EvidenceMatcher> removeVendor = new ArrayList<>();
    /**
     * The list of product evidence to remove.
     */
    private final List<EvidenceMatcher> removeProduct = new ArrayList<>();
    /**
     * The list of version evidence to remove.
     */
    private final List<EvidenceMatcher> removeVersion = new ArrayList<>();

    /**
     * Adds the filename evidence to the collection.
     *
     * @param filename the filename to add
     */
    public void addFilename(PropertyType filename) {
        this.fileNames.add(filename);
    }

    /**
     * Returns the list of fileName evidence to match against.
     *
     * @return the list of fileName evidence to match against
     */
    public List<PropertyType> getFileNames() {
        return fileNames;
    }

    /**
     * Adds a given product to the list of evidence to matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param regex whether value is a regex
     * @param confidence the confidence of the evidence
     */
    public void addGivenProduct(String source, String name, String value, boolean regex, Confidence confidence) {
        givenProduct.add(new EvidenceMatcher(source, name, value, regex, confidence));
    }

    /**
     * Get the value of givenProduct.
     *
     * @return the value of givenProduct
     */
    public List<EvidenceMatcher> getGivenProduct() {
        return givenProduct;
    }

    /**
     * Adds a given vendors to the list of evidence to matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param regex whether value is a regex
     * @param confidence the confidence of the evidence
     */
    public void addGivenVendor(String source, String name, String value, boolean regex, Confidence confidence) {
        givenVendor.add(new EvidenceMatcher(source, name, value, regex, confidence));
    }

    /**
     * Get the value of givenVendor.
     *
     * @return the value of givenVendor
     */
    public List<EvidenceMatcher> getGivenVendor() {
        return givenVendor;
    }

    /**
     * Adds a given product to the list of evidence to add when matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param confidence the confidence of the evidence
     */
    public void addAddProduct(String source, String name, String value, Confidence confidence) {
        addProduct.add(new Evidence(source, name, value, confidence));
    }

    /**
     * Get the value of addProduct.
     *
     * @return the value of addProduct
     */
    public List<Evidence> getAddProduct() {
        return addProduct;
    }

    /**
     * Adds a given version to the list of evidence to add when matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param confidence the confidence of the evidence
     */
    public void addAddVersion(String source, String name, String value, Confidence confidence) {
        addVersion.add(new Evidence(source, name, value, confidence));
    }

    /**
     * Get the value of addVersion.
     *
     * @return the value of addVersion
     */
    public List<Evidence> getAddVersion() {
        return addVersion;
    }

    /**
     * Adds a given vendor to the list of evidence to add when matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param confidence the confidence of the evidence
     */
    public void addAddVendor(String source, String name, String value, Confidence confidence) {
        addVendor.add(new Evidence(source, name, value, confidence));
    }

    /**
     * Get the value of addVendor.
     *
     * @return the value of addVendor
     */
    public List<Evidence> getAddVendor() {
        return addVendor;
    }

    /**
     * Adds a given vendor to the list of evidence to remove when matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param regex whether value is a regex
     * @param confidence the confidence of the evidence
     */
    public void addRemoveVendor(String source, String name, String value, boolean regex, Confidence confidence) {
        removeVendor.add(new EvidenceMatcher(source, name, value, regex, confidence));
    }
    /**
     * Get the value of removeVendor.
     *
     * @return the value of removeVendor
     */
    public List<EvidenceMatcher> getRemoveVendor() {
        return removeVendor;
    }
    /**
     * Adds a given product to the list of evidence to remove when matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param regex whether value is a regex
     * @param confidence the confidence of the evidence
     */
    public void addRemoveProduct(String source, String name, String value, boolean regex, Confidence confidence) {
        removeProduct.add(new EvidenceMatcher(source, name, value, regex, confidence));
    }
    /**
     * Get the value of removeProduct.
     *
     * @return the value of removeProduct
     */
    public List<EvidenceMatcher> getRemoveProduct() {
        return removeProduct;
    }
    /**
     * Adds a given version to the list of evidence to remove when matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param regex whether value is a regex
     * @param confidence the confidence of the evidence
     */
    public void addRemoveVersion(String source, String name, String value, boolean regex, Confidence confidence) {
        removeVersion.add(new EvidenceMatcher(source, name, value, regex, confidence));
    }
    /**
     * Get the value of removeVersion.
     *
     * @return the value of removeVersion
     */
    public List<EvidenceMatcher> getRemoveVersion() {
        return removeVersion;
    }
    /**
     * Adds a given version to the list of evidence to match.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param regex whether value is a regex
     * @param confidence the confidence of the evidence
     */
    public void addGivenVersion(String source, String name, String value, boolean regex, Confidence confidence) {
        givenVersion.add(new EvidenceMatcher(source, name, value, regex, confidence));
    }
    /**
     * Get the value of givenVersion.
     *
     * @return the value of givenVersion
     */
    public List<EvidenceMatcher> getGivenVersion() {
        return givenVersion;
    }
}
