package com.horizen.sigproofnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;

import java.util.List;

public class NaiveThresholdSigProof {

    private static native FieldElement nativeCreateMsgToSign(BackwardTransfer[] bt,
                                                             byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash);

    public static FieldElement createMsgToSign(BackwardTransfer[] bt,
                                               byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash) {
        return nativeCreateMsgToSign(bt, endEpochBlockHash, prevEndEpochBlockHash);
    }

    private static native byte[] nativeCreateProof(BackwardTransfer[] bt,
                                                   byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                                   SchnorrSignature[] schnorrSignatures, SchnorrPublicKey[] schnorrPublicKeys,
                                                   long threshold, String provingKeyPath);

    public static byte[] createProof(List<BackwardTransfer> btList,
                                     byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                     List<SchnorrSignature> schnorrSignatureList, List<SchnorrPublicKey> schnorrPublicKeyList,
                                     long threshold, String provingKeyPath) {
        return nativeCreateProof(btList.toArray(new BackwardTransfer[0]), endEpochBlockHash, prevEndEpochBlockHash,
                schnorrSignatureList.toArray(new SchnorrSignature[0]), schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, provingKeyPath);
    }
}
