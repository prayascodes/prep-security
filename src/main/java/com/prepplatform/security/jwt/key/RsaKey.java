package com.prepplatform.security.jwt.key;

import com.prepplatform.security.jwt.SignatureAlgorithm;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public record RsaKey(SignatureAlgorithm alg, String kid, RSAPublicKey pubKey,
                     RSAPrivateKey privKey) implements SigningKey {

}
