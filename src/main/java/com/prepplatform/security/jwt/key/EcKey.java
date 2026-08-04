package com.prepplatform.security.jwt.key;

import com.prepplatform.security.jwt.SignatureAlgorithm;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public record EcKey(SignatureAlgorithm alg, String kid, ECPublicKey pubKey,
                    ECPrivateKey privKey) implements SigningKey {

}
