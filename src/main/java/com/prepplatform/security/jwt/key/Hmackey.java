package com.prepplatform.security.jwt.key;

import com.prepplatform.security.jwt.SignatureAlgorithm;

import javax.crypto.SecretKey;

public record Hmackey(SignatureAlgorithm alg, String kid, SecretKey secretKey) implements
    SigningKey {

}
