package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;

/**
 * implementation of SHA-3 based on Keccak-simple.c from http://keccak.noekeon.org/
 * 
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class SHA3Digest {

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
    
    private void keccakPermutation(char[] u8state) {
        displayStateAsBytes(1, "Input of permutation", u8state);
        
        // convert to state as words first, not done in the C version due to char[] shenanigans
        stateAsWords(u8state, u64State);
        keccakPermutationOnWords(u64State)
        statsAsBytes(u64State, u8state);
        
        displayStateAsBytes(1, "state after permutation", u8state);
    }
    
    private void keccakPermutationAfterXor(char[] state, final char[] data, final int dataLengthInBytes) {
        
        for (int i=0; i< dataLengthInBytes;i++) {
            state[i] ^= data[i];
        }
        keccakPermutation(state);
    }
    
    private void keccakPermutationOnWords(long[] u64state) {
        int i;
        
        displayStateAs64bitWords(3, "Same with lanes as 64-bit words", u64state);
        
        for (int i=0; i<24; i++) {
            displayRoundNumber(3, i);
            
            theta(u64state);
            displayStateAs64bitWords(i, "After theta", u64state);
            
            rho(u64state);
            displayStateAs64bitWords(i, "After rho", u64state);
            
            pi(u64state);
            displayStateAs64bitWords(i, "After pi", u64state);
            
            chi(u64state);
            displayStateAs64bitWords(i, "After chi", u64state);
            
            iota(u64state, i);
            displayStateAs64bitWords(i, "After iota", u64state);
        }
    }
    
    // A is the u64state
    private void theta(long[] A) {
        long[] C = new long[5];
        long[] D = new long[5];
        
        for (int x=0; x<5; x++) {
            C[x] = 0;
            for (int y=0; y<5; y++) {
                C[x] ^= A[(((x)%5)+5*((y)%5))];
            }
        }
        
        for (int x=0; x<5; x++) {
            // wtf 1 != 0 !!
            int p = (x+1)%5;
            D[x] = ((1 != 0) ? ((((long)C[p]) << 1) ^ (((long)C[p]) >> (64-1))) : C[p]) ^ C[(x+4)%5];
        }
        
        for (int x=0; x<5; x++) {
            for (int y=0; y<5; y++) {
                A[(((x)%5)+5*((y)%5))] ^= D[x];
            }
        }
    }
    
    private void rho(long[] A) {
        for (int x=0; x<5; x++) {
            for (int y=0; y<5; y++) {
                int p = (((x)%5)+5*((y)%5));
                A[p] = ((_keccakRhoOffsets[p] != 0) ? ((((long)A[p]) << _keccakRhoOffsets[p]) ^ (((long)A[p]) >> (64-_keccakRhoOffsets[p]))) : A[p]);
            }
        }
    }
    
    private void pi(long[] A) {
        long[] tempA = new long[25];
        
        for (int x=0; x<5; x++) {
            for (int y=0; y<5; y++) {
                int p = (((x)%5)+5*((y)%5));
                tempA[p] = A[p];
            }
        }
        
        for (int x=0; x<5; x++) {
            for (int y=0; y<5; y++) {
                A[(((0*x+1*y)%5)+5*((2*x+3*y)%5))] = tempA[(((x)%5)+5*((y)%5))];
            }
        }
    }
    
    private void chi(long[] A) {
        long[] C = new long[5];
        
        for (int y=0; y<5; y++) {
            for (int x=0; x<5; x++) {
                C[x] = A[(((x)%5)+5*((y)%5))] ^ ((~A[(((x+1)%5)+5*((y)%5))]) & A[(((x+2)%5)+5*((y)%5))]);
            }
            for (int x=0; x<5; x++) {
                A[(((x)%5)+5*((y)%5))] = C[x];
            }
        }
    }
    
    private void iota(long[] A, int indexRound) {
        A[(((0)%5)+5*((0)%5))] ^= _keccakRoundConstants[indexRound];
    }
    
    
    private void displayStateAsBytes(int i, String comment, char[] u8state) {
        System.out.println("displayStateAsBytes");
    }
    
    private void displayStateAs64bitWords(int i, String comment, long[] u64state) {
        System.out.println("displayStateAs64bitWords");
    }
    
    private void displayRoundNumber(int i, int roundNumber) {
        System.out.println("displayRoundNumber");
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
