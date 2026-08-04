package com.prepplatform.security.jwt.key;

import com.prepplatform.security.jwt.SignatureAlgorithm;
import org.jspecify.annotations.NullMarked;

@NullMarked
public interface SigningKey {

  SignatureAlgorithm alg();

  String kid();
}
