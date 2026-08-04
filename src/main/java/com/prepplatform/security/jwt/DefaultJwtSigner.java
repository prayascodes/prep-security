package com.prepplatform.security.jwt;

import com.prepplatform.security.AuthenticatedPrincipal;
import com.prepplatform.security.jwt.spi.ClockProvider;
import com.prepplatform.security.jwt.spi.KeyProvider;

public class DefaultJwtSigner extends JwtHelper implements JwtSigner {

  public DefaultJwtSigner(KeyProvider keyProvider, ClockProvider clock, JwtProperties props) {
    super(keyProvider, clock, props);
  }

  @Override
  public String sign(AuthenticatedPrincipal principal, JwtTokenType type) {
    return super.sign(principal, type);
  }
}
