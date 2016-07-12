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
public class HintRule {

    /**
     * The list of file names to match.
     */
    private final List<PropertyType> filenames = new ArrayList<PropertyType>();

    /**
     * Adds the filename evidence to the collection.
     *
     * @param filename the filename to add
     */
    public void addFilename(PropertyType filename) {
        this.filenames.add(filename);
    }

    /**
     * Returns the list of filename evidence to match against.
     *
     * @return the list of filename evidence to match against
     */
    public List<PropertyType> getFilenames() {
        return filenames;
    }
    /**
     * The list of product evidence that is being matched.
     */
    private final List<Evidence> givenProduct = new ArrayList<Evidence>();

    /**
     * Adds a given product to the list of evidence to matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param confidence the confidence of the evidence
     */
    public void addGivenProduct(String source, String name, String value, Confidence confidence) {
        givenProduct.add(new Evidence(source, name, value, confidence));
    }

    /**
     * Get the value of givenProduct
     *
     * @return the value of givenProduct.
     */
    public List<Evidence> getGivenProduct() {
        return givenProduct;
    }

    /**
     * The list of vendor evidence that is being matched.
     */
    private final List<Evidence> givenVendor = new ArrayList<Evidence>();

    /**
     * Adds a given vendors to the list of evidence to matched.
     *
     * @param source the source of the evidence
     * @param name the name of the evidence
     * @param value the value of the evidence
     * @param confidence the confidence of the evidence
     */
    public void addGivenVendor(String source, String name, String value, Confidence confidence) {
        givenVendor.add(new Evidence(source, name, value, confidence));
    }

    /**
     * Get the value of givenVendor.
     *
     * @return the value of givenVendor
     */
    public List<Evidence> getGivenVendor() {
        return givenVendor;
    }

    /**
     * The list of product evidence to add.
     */
    private final List<Evidence> addProduct = new ArrayList<Evidence>();

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
     * The list of vendor hints to add.
     */
    private final List<Evidence> addVendor = new ArrayList<Evidence>();

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
}
