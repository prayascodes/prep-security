package com.prepplatform.security.jwt.spi;

import com.prepplatform.security.jwt.key.SigningKey;

public interface KeyProvider {

  SigningKey getActiveKey();

  SigningKey getKey(String kid);
}
