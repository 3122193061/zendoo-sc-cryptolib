package com.horizen.scutxonative;

import static org.junit.Assert.assertEquals;

import java.util.Random;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Utils;

import org.junit.Test;

public class ScUtxoOutputTest {
    static long seed = 1234567890L;
    static String expectedScUtxoOutputNullifierHex =
        "E9B4150240894257D08C5C2FAA8565062FB6F31DEFFFC3A9D196F790C971D71F";

    @Test
    public void testScUtxoOutputNullifier() {

        // Generate random ForwardTransferOutput and get its nullifier
        Random r = new Random(seed);
        FieldElement nullifier = ScUtxoOutput.getRandom(r).getNullifier();
        byte[] nullifierBytes = nullifier.serializeFieldElement();

        // Check equality with expected one
        assertEquals(expectedScUtxoOutputNullifierHex, Utils.bytesToHex(nullifierBytes));

        // Free memory
        nullifier.close();
    }
}
