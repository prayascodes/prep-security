package com.prepplatform.security.jwt;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.prepplatform.security.AuthenticatedPrincipal;
import com.prepplatform.security.jwt.key.EcKey;
import com.prepplatform.security.jwt.key.Hmackey;
import com.prepplatform.security.jwt.key.RsaKey;
import com.prepplatform.security.jwt.key.SigningKey;
import com.prepplatform.security.jwt.spi.ClockProvider;
import com.prepplatform.security.jwt.spi.KeyProvider;

import java.text.ParseException;
import java.time.Duration;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

abstract class JwtHelper {

  protected final Set<KeyOperation> keyOps = Set.of(KeyOperation.SIGN, KeyOperation.VERIFY);

  protected final KeyProvider keyProvider;
  protected final ClockProvider clock;
  protected final JwtProperties props;

  JwtHelper(KeyProvider keyProvider, ClockProvider clock, JwtProperties props) {
    this.keyProvider = keyProvider;
    this.clock = clock;
    this.props = props;
  }

  protected String sign(AuthenticatedPrincipal principal, JwtTokenType type) {
    var jwk = toJwk(keyProvider.getActiveKey());
    var claims = buildClaims(principal, type);
    var signedJwt = createSignedJwt(jwk, claims);
    var signer = toSigner(jwk);
    sign(signedJwt, signer);
    return signedJwt.serialize();
  }

  private JWK toJwk(SigningKey sgk) {
    return switch (sgk) {
      case RsaKey rsa -> toRsa(rsa);
      case EcKey ec -> toEc(ec);
      case Hmackey hmac -> toOctet(hmac);
      default -> throw new AssertionError("Unhandled SigningKey impl: " + sgk.getClass().getName());
    };
  }

  private RSAKey toRsa(RsaKey rsa) {
    return new RSAKey
        .Builder(rsa.pubKey())
        .algorithm(Algorithm.parse(rsa.alg().name()))
        .keyUse(KeyUse.SIGNATURE)
        .keyID(rsa.kid())
        .privateKey(rsa.privKey())
        .keyOperations(keyOps)
        .build();
  }

  private ECKey toEc(EcKey ec) {
    return new ECKey
        .Builder(Curve.forECParameterSpec(ec.pubKey().getParams()), ec.pubKey())
        .algorithm(Algorithm.parse(ec.alg().name()))
        .keyUse(KeyUse.SIGNATURE)
        .keyID(ec.kid())
        .privateKey(ec.privKey())
        .keyOperations(keyOps)
        .build();
  }

  private OctetSequenceKey toOctet(Hmackey hmac) {
    return new OctetSequenceKey
        .Builder(hmac.secretKey())
        .algorithm(Algorithm.parse(hmac.alg().name()))
        .keyUse(KeyUse.SIGNATURE)
        .keyID(hmac.kid())
        .keyOperations(keyOps)
        .build();
  }

  private JWTClaimsSet buildClaims(AuthenticatedPrincipal principal, JwtTokenType type) {
    var now = clock.clock().instant();

    return new JWTClaimsSet.Builder().jwtID(UUID.randomUUID().toString()).serializeNullClaims(false)
        .issuer(props.issuer()).audience(props.audiences()).subject(principal.id())
        .issueTime(Date.from(now)).notBeforeTime(Date.from(now))
        .expirationTime(Date.from(now.plus(getTtl(type))))
        .claim(ClaimAttrs.TOKEN_TYPE.name, type.name)
        .claim(ClaimAttrs.AUTHORITIES.name, principal.authorities())
        .claim(ClaimAttrs.ATTRS.name, principal.attributes()).build();
  }

  private Duration getTtl(JwtTokenType type) {
    return switch (type) {
      case REFRESH -> props.refreshTtl();
      case ACCESS -> props.accessTtl();
    };
  }

  private SignedJWT createSignedJwt(JWK jwk, JWTClaimsSet claims) {
    var header = new JWSHeader.Builder(JWSAlgorithm.parse(jwk.getAlgorithm().getName())).keyID(
        jwk.getKeyID()).type(JOSEObjectType.JWT).build();

    return new SignedJWT(header, claims);
  }

  private JWSSigner toSigner(JWK jwk) {
    return execute(() -> switch (jwk) {
      case RSAKey rsa -> new RSASSASigner(rsa);
      case ECKey ec -> new ECDSASigner(ec);
      case OctetSequenceKey okt -> new MACSigner(okt);
      case OctetKeyPair okp -> new Ed25519Signer(okp);
      default -> throw new AssertionError("Unhandled Signer impl: " + jwk.getClass().getName());
    }, () -> new JwtSigningException("Failed to create signer for signing jwt token."));
  }

  private void sign(SignedJWT signedJwt, JWSSigner signer) {
    execute(() -> signedJwt.sign(signer),
        () -> "Failed to sign jwt with signer: " + signer.getClass().getName());
  }

  private <T> T execute(JoseSupplier<T> action, Supplier<? extends JwtException> exception) {
    try {
      return action.get();
    } catch (JOSEException cause) {
      var ex = exception.get();
      ex.setCause(cause);
      throw ex;
    }
  }

  private void execute(JoseRunnable action, Supplier<String> message) {
    try {
      action.run();
    } catch (JOSEException e) {
      throw new JwtSigningException(message.get(), e);
    }
  }

  protected AuthenticatedPrincipal verify(String token) {
    var signedJwt = parse(token);
    var kid = getKid(signedJwt);
    var jwk = toJwk(keyProvider.getKey(kid));
    validateJwt(signedJwt, toVerifier(jwk));
    return toPrincipal(extractClaims(signedJwt));
  }

  private SignedJWT parse(String token) {
    try {
      return SignedJWT.parse(token);
    } catch (ParseException e) {
      throw new JwtVerificationException("JWT is malformed.");
    }
  }

  private String getKid(SignedJWT signedJWT) {
    var kid = signedJWT.getHeader().getKeyID();

    if (kid == null || kid.isBlank()) {
      throw new JwtVerificationException("JWT header does not contain a key identifier ('kid').");
    }

    return kid;
  }

  private JWSVerifier toVerifier(JWK jwk) {
    return execute(() -> switch (jwk) {
      case RSAKey rsa -> new RSASSAVerifier(rsa);
      case ECKey ec -> new ECDSAVerifier(ec);
      case OctetSequenceKey okt -> new MACVerifier(okt);
      case OctetKeyPair okp -> new Ed25519Verifier(okp);
      default -> throw new AssertionError("Unhandled Verifier impl: " + jwk.getClass().getName());
    }, () -> new JwtVerificationException("Failed to create verifier for verifying jwt token."));
  }

  private void validateJwt(SignedJWT signedJWT, JWSVerifier verifier) {
    if (!execute(() -> signedJWT.verify(verifier),
        () -> new JwtVerificationException("Error while verifying JWT signature."))) {
      throw new JwtVerificationException("Invalid JWT signature.");
    }
  }

  private JWTClaimsSet extractClaims(SignedJWT verifiedJwt) {
    try {
      var claims = verifiedJwt.getJWTClaimsSet();
      validateLifetime(claims);
      return claims;
    } catch (ParseException e) {
      throw new JwtVerificationException("Verified JWT contains invalid claims.", e);
    }
  }

  private void validateLifetime(JWTClaimsSet claims) {
    var now = clock.clock().instant();
    var notBefore = claims.getNotBeforeTime();

    if (notBefore != null && notBefore.toInstant().isAfter(now)) {
      throw new JwtVerificationException("JWT is not yet valid.");
    }

    var exp = claims.getExpirationTime();

    if (exp == null || !exp.toInstant().isAfter(now)) {
      throw new JwtVerificationException("JWT has expired.");
    }
  }

  @SuppressWarnings("unchecked")
  private AuthenticatedPrincipal toPrincipal(JWTClaimsSet claims) {
    var authorities = Optional.ofNullable(
            (Collection<String>) claims.getClaim(ClaimAttrs.AUTHORITIES.name))
        .filter(c -> !c.isEmpty())
        .map(HashSet::new)
        .orElseThrow(() -> new JwtVerificationException(
            "Verified JWT contains an empty 'authorities' claim."));

    var attributes = Optional.ofNullable(
            (Map<String, Object>) claims.getClaim(ClaimAttrs.ATTRS.name))
        .filter(c -> !c.isEmpty())
        .map(HashMap::new)
        .orElseThrow(
            () -> new JwtVerificationException("Verified JWT contains an empty 'attrs' claim."));

    return new AuthenticatedPrincipal(claims.getSubject(), authorities, attributes);
  }

  @FunctionalInterface
  private interface JoseSupplier<T> {

    T get() throws JOSEException;
  }

  @FunctionalInterface
  private interface JoseRunnable {

    void run() throws JOSEException;
  }
}
