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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

/**
 * A generic pair of elements.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class Pair<K, V> {

    /**
     * Constructs a new empty pair.
     */
    public Pair() {
    }

    /**
     * Constructs a new Pair with the given left and right values.
     *
     * @param left the value for the left pair
     * @param right the value for the right pair
     */
    public Pair(K left, V right) {
        this.left = left;
        this.right = right;
    }
    /**
     * The left element of the pair.
     */
    private K left = null;

    /**
     * Get the value of left
     *
     * @return the value of left
     */
    public K getLeft() {
        return left;
    }

    /**
     * Set the value of left
     *
     * @param left new value of left
     */
    public void setLeft(K left) {
        this.left = left;
    }
    /**
     * The right element of the pair.
     */
    private V right = null;

    /**
     * Get the value of right
     *
     * @return the value of right
     */
    public V getRight() {
        return right;
    }

    /**
     * Set the value of right
     *
     * @param right new value of right
     */
    public void setRight(V right) {
        this.right = right;
    }

    /**
     * Generates the hash code using the hash codes from the contained objects.
     *
     * @return the hash code of the Pair
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 53 * hash + (this.left != null ? this.left.hashCode() : 0);
        hash = 53 * hash + (this.right != null ? this.right.hashCode() : 0);
        return hash;
    }

    /**
     * Determines the equality of this and the provided object.
     *
     * @param obj the {@link Object} to check for equality to this
     * @return true if this and the provided {@link Object} are equal; otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Pair<?, ?> other = (Pair<?, ?>) obj;
        if (this.left != other.left && (this.left == null || !this.left.equals(other.left))) {
            return false;
        }
        if (this.right != other.right && (this.right == null || !this.right.equals(other.right))) {
            return false;
        }
        return true;
    }
}
