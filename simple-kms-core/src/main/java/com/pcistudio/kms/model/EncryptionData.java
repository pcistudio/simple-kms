package com.pcistudio.kms.model;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.nio.ByteBuffer;

@SuppressFBWarnings({"EI_EXPOSE_REP2", "EI_EXPOSE_REP"})
public record EncryptionData(ByteBuffer encryptedKey, ByteBuffer encryptedData) {
}
