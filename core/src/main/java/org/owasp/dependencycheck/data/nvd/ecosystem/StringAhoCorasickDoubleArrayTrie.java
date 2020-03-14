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

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
     * Parse text
     *
     * @param text      The text
     * @param processor A processor which handles the output
     */
    public void parseText(String text, IHitFull<V> processor)
    {
        int position = 1;
        int currentState = 0;
        for (int i = 0; i < text.length(); i++)
        {
            currentState = getState(currentState, text.charAt(i));
            int[] hitArray = output[currentState];
            if (hitArray != null)
            {
                for (int hit : hitArray)
                {
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
    private int getState(int currentState, char character)
    {
        int newCurrentState = transitionWithRoot(currentState, character);  // 先按success跳转
        while (newCurrentState == -1) // 跳转失败的话，按failure跳转
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
