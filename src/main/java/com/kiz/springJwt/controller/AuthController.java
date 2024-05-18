package com.kiz.springJwt.controller;

import com.kiz.springJwt.model.Response.AuthenticationResponse;
import com.kiz.springJwt.model.User;
import com.kiz.springJwt.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final AuthenticationService authService;

    public AuthController(AuthenticationService authenticationService) {
        this.authService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody User request){

        return ResponseEntity.ok(authService.register(request));

    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody User request){

        return ResponseEntity.ok(authService.login(request));

    }

    @GetMapping("/check")
    public ResponseEntity<String> check(){

        return ResponseEntity.ok("Secured");

    }


    @GetMapping("/admin")
    public ResponseEntity<String> adminOnly(){

        return ResponseEntity.ok("Hello Admnin");

    }


    @PostMapping("/refresh_token")
    public ResponseEntity refrehToken(HttpServletRequest request, HttpServletResponse response){

        return authService.refreshToken(request, response);

    }


}
