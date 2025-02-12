package com.pcistudio.kms;

import com.pcistudio.kms.model.EncryptedKeyInfo;

public interface RotationPolicy {
    boolean shouldRotateKey(EncryptedKeyInfo keyInfo);
}
