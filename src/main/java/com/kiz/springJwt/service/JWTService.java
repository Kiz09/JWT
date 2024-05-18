package com.kiz.springJwt.service;

import com.kiz.springJwt.Repository.TokenRepository;
import com.kiz.springJwt.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.Optional;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
public class JWTService {

    @Value("${application.security.jwt.secret-key}")
    private String SECRET_KEY;

    @Value("${application.security.jwt.access-token}")
    private Long ACCESS_TOKEN;

    @Value("${application.security.jwt.refresh-token}")
    private Long REFRESH_TOKEN;

    private TokenRepository tokenRepository;

    public JWTService(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver){
        Claims claims = extractAllClaims(token);

        return resolver.apply(claims);

    }

    public String extractUsername(String token){

        return extractClaim(token, Claims::getSubject);

    }

    public boolean isValid(String token, UserDetails user){

        String userName  =  extractUsername(token);

        boolean isValidToken = tokenRepository.findByAccessToken(token).map(t-> !t.isLoggedOut()).orElse(false);

        return (userName.equals(user.getUsername())  && !isTokenExpired(token) && isValidToken);

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

    private String generateToken(User user, long expirationTime){

        return Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSigninKey())
                .compact();
    }

    public String generateAccesToken(User user){

        return generateToken(user, ACCESS_TOKEN); //Set now for 10 seconds, 24 hrs is 8640000
    }

    public String generateRefreshToken(User user){

        return generateToken(user, REFRESH_TOKEN); //Set now for 30 seconds, 7 days is 60480000
    }




    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isValidRefreshToken(String token, User user) {

        String userName  =  extractUsername(token);

        boolean isValidRefreshToken = tokenRepository.findByRefreshToken(token).map(t-> !t.isLoggedOut()).orElse(false);


        return (userName.equals(user.getUsername())  && !isTokenExpired(token) && isValidRefreshToken);

    }
}
