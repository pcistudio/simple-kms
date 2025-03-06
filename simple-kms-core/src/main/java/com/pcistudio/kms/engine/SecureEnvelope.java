package com.pcistudio.kms.engine;

import com.pcistudio.kms.model.EncryptionData;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.nio.ByteBuffer;

//@SuppressFBWarnings({"EI_EXPOSE_REP2", "EI_EXPOSE_REP"})
//public record ProviderEncryptionData(String p, ByteBuffer ek, ByteBuffer ed) {
//    public static ProviderEncryptionData of(String provider, EncryptionData encryptionData) {
//        return new ProviderEncryptionData(provider, encryptionData.encryptedKey(), encryptionData.encryptedData());
//    }
//}
@SuppressFBWarnings("EI_EXPOSE_BUF")
public class SecureEnvelope {
    private String p;
    private byte[] ek;
    private byte[] ed;

    public SecureEnvelope(String p, ByteBuffer ekBuffer, ByteBuffer edBuffer) {
        this.p = p;

        this.ek = new byte[ekBuffer.remaining()];
        ekBuffer.get(this.ek);
        this.ed = new byte[edBuffer.remaining()];
        edBuffer.get(this.ed);
    }

    public String getP() {
        return p;
    }
    public ByteBuffer getEk() {
        return ByteBuffer.wrap(ek);
    }
    public ByteBuffer getEd() {
        return ByteBuffer.wrap(ed);
    }
    public static SecureEnvelope of(String provider, EncryptionData encryptionData) {
        return new SecureEnvelope(provider, encryptionData.encryptedKey(), encryptionData.encryptedData());
    }
}
