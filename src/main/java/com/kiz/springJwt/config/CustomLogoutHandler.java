package com.kiz.springJwt.config;

import com.kiz.springJwt.Repository.TokenRepository;
import com.kiz.springJwt.model.Token;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.NoSuchElementException;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;

@Component
public class CustomLogoutHandler implements LogoutHandler {

    private final TokenRepository tokenRepository;

    public CustomLogoutHandler(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            response.setStatus(400);
            throw new NoSuchElementException();
        }

        String token = authHeader.substring(7);

        // get stored token from database
        // invalidate token, make loggout true
        // save the token
        Token storedToken = tokenRepository.findByAccessToken(token).orElseThrow(NoSuchElementException::new);

        if(Objects.nonNull(storedToken)){
            storedToken.setLoggedOut(true);
            tokenRepository.save(storedToken);
        }
    }
}
