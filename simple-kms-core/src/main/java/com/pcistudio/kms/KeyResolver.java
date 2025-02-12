package com.pcistudio.kms;

import com.pcistudio.kms.model.KeyInfo;

import javax.crypto.SecretKey;

public interface KeyResolver {

    SecretKey resolve(int keyId);

    KeyInfo currentKey();

    String resolverName();
}
