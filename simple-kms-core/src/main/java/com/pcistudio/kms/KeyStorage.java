package com.pcistudio.kms;

import com.pcistudio.kms.model.EncryptedKeyInfo;
import edu.umd.cs.findbugs.annotations.Nullable;

import java.nio.ByteBuffer;

/**
 * Interface for storing encrypted keys. Most likely this will be a database.
 */
public interface KeyStorage {
    EncryptedKeyInfo addKey(ByteBuffer key);

    EncryptedKeyInfo get(int id);

    @Nullable
    EncryptedKeyInfo getCurrentKey();
}
