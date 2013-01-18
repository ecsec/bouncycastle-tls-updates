package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;

/**
 * implementation of SHA-3 based on Keccak-simple.c from http://keccak.noekeon.org/
 * 
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class SHA3Digest {

    /*
     * Aargh, the use of 64bit values means I have no where to go with unsigned - speak to Ox
     * 
     */
    private long[]   _keccakRoundConstants = new long[24];
    private int[]    _keccakRhoOffsets = new int[25];
    
    private void fromBytestoWords(long[] stateAsWords, final char[] state) {
        
        for (int i=0;i<(1600/64);i++) {
            stateAsWords[i] = 0;
            for (int j=0; j<(64/8); j++) {
                stateAsWords[i] |= (long)(state[i*(64/8)+j]) << (8*j);
            }
        }
    }
    
    private void fromWordsToBytes(char[] state, final long[] stateAsWords) {
                
        for (int i=0;i<(1600/64); i++) {
            for (int j=0; j<(64/8); j++) {
                state[i*(64/8)+j] = (char)((stateAsWords[i] >> (8*j)) & 0xFF);
            }
        }
    }
    
    private void keccakPermutation(char[] state) {
        displayStateAsBytes(1, "Input of permutation", state);
        
        // convert to state as words first, not done in the C version due to char[] shenanigans
        stateAsWords();
        keccakPermutationOnWords(stateAsWords)
        statsAsBytes();
    }
    
    
    


    /**
     * Return the size of block that the compression function is applied to in bytes.
     *
     * @return internal byte length of a block.
     */
    public int getByteLength()
    {
        return _x.length * 8;
    }
}
