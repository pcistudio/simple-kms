package com.pcistudio.kms;

public interface EncryptionProvider {
    EncryptionContext getContext();
    String getName();
}
