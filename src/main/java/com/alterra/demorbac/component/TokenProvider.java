package com.alterra.demorbac.component;

import java.io.Serializable;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class TokenProvider implements Serializable {

    private static final long serialVersionUID = -1403857064104614481L;

    @Value("${jwt.token.validity:18000}")
    private long tokenExpires;

    @Value("${jwt.signing.key:lLz0wjFXoLhdj4xfGX4gc192O29JBRkcSF9DmPkyYVOn6gCAUa}")
    private String signingKey;

    @Value("${jwt.authorities.key:roles}")
    private String authoritiesKey;

    private Key key;

    @PostConstruct
    public void init() {
        final byte[] signingKeyBytes = Base64.getDecoder().decode(signingKey);
        key = new SecretKeySpec(signingKeyBytes, 0, signingKeyBytes.length, SignatureAlgorithm.HS256.getJcaName());
    }


    public String getUsername(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDate(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    private <T> T getClaimFromToken(String token, Function<Claims, T> claimResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isExpired(String token) {
        final Date expirationDate = getExpirationDate(token);
        return expirationDate.before(new Date());
    }

    public String generateToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(authoritiesKey, authorities)
                .signWith(key)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpires))
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = getUsername(token);
        return (username.equals(userDetails.getUsername()) && !isExpired(token));
    }

    public Authentication getAuthenticationToken(final String token, final Authentication authentication, final UserDetails userDetails) {
        final JwtParser jwtParser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();
        
        final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);

        final Claims claims = claimsJws.getBody();

        final Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(authoritiesKey).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        
        return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
    }
    
}
