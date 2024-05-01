package com.kiz.springJwt.service;

import com.kiz.springJwt.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.function.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
public class JWTService {

    private final String SECRET_KEY="fb9ae3a7a67f673400d9b728a05e9776b29c73946ca01d9bb486b892db299014";

    public <T> T extractClaim(String token, Function<Claims, T> resolver){
        Claims claims = extractAllClaims(token);

        return resolver.apply(claims);

    }

    public String extractUsername(String token){

        return extractClaim(token, Claims::getSubject);

    }

    public boolean isValid(String token, UserDetails user){

        String userName  =  extractUsername(token);

        return (userName.equals(user.getUsername())  && !isTokenExpired(token));

    }

    private boolean isTokenExpired(String token) {

        return extractExpiration(token).before(new Date());

    }

    private Date extractExpiration(String token) {

        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts.parser().verifyWith(getSigninKey()).build().parseSignedClaims(token).getPayload();

    }

    private String generateToken(User user){

        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24*60*60*1000))
                .signWith(getSigninKey())
                .compact();

        return token;
    }

    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes);
    }

}