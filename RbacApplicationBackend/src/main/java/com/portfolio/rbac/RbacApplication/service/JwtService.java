package com.portfolio.rbac.RbacApplication.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JwtService {
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expirationMs}")
    private long jwtExpirationMs;

    public String extractUsername(String token) {
        return Jwts.parser().setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes())).build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public String generateToken(UserDetails userDetails, Map<String, Object> extractClaims) {
        Date now = new Date();
        Date expiry = new Date(now.getTime()+jwtExpirationMs);
        return Jwts.builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes()), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        Date exp = Jwts.parser().setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes())).build()
                .parseClaimsJws(token).getBody().getExpiration();
        boolean valid = username.equals(userDetails.getUsername()) && exp.after(new Date());

        if (!valid) logger.debug("Invalid token for user: {}", username);
        return valid;
    }
}
