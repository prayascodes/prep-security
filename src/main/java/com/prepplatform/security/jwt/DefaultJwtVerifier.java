package com.prepplatform.security.jwt;

import com.prepplatform.security.AuthenticatedPrincipal;
import com.prepplatform.security.jwt.spi.ClockProvider;
import com.prepplatform.security.jwt.spi.KeyProvider;

public class DefaultJwtVerifier extends JwtHelper implements JwtVerifier {

  public DefaultJwtVerifier(KeyProvider keyProvider, ClockProvider clock, JwtProperties props) {
    super(keyProvider, clock, props);
  }

  @Override
  public AuthenticatedPrincipal verify(String token) {
    return super.verify(token);
  }
}
