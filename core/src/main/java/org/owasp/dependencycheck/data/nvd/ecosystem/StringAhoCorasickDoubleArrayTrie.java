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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.ecosystem;

import com.hankcs.algorithm.AhoCorasickDoubleArrayTrie;

/**
 *
 * Add method for String and IHitFull.
 *
 * TODO: Put in PR to relevant project
 *
 * @param <V>
 */
public class StringAhoCorasickDoubleArrayTrie<V> extends AhoCorasickDoubleArrayTrie<V> {

    private static final long serialVersionUID = -5923428681217396309L;

    /**
     * Parse text
     *
     * @param text The text
     * @param processor A processor which handles the output
     */
    public void parseText(String text, IHitFull<V> processor) {
        int position = 1;
        int currentState = 0;
        for (int i = 0; i < text.length(); i++) {
            currentState = getState(currentState, text.charAt(i));
            int[] hitArray = output[currentState];
            if (hitArray != null) {
                for (int hit : hitArray) {
                    processor.hit(position - l[hit], position, v[hit], hit);
                }
            }
            ++position;
        }
    }

    /**
     * transmit state, supports failure function
     *
     * @param currentState
     * @param character
     * @return
     */
    private int getState(int currentState, char character) {
        int newCurrentState = transitionWithRoot(currentState, character);  //success
        while (newCurrentState == -1) //failure
        {
            currentState = fail[currentState];
            newCurrentState = transitionWithRoot(currentState, character);
        }
        return newCurrentState;
    }

    public V[] getValues() {
        return v;
    }
}
