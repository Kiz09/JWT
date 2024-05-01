package com.kiz.springJwt.controller;

import com.kiz.springJwt.model.AuthenticationResponse;
import com.kiz.springJwt.model.User;
import com.kiz.springJwt.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final AuthenticationService authenticationService;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody User request){

        return ResponseEntity.ok(authenticationService.register(request));

    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody User request){

        return ResponseEntity.ok(authenticationService.login(request));

    }

    @GetMapping("/check")
    public ResponseEntity<String> check(){

        return ResponseEntity.ok("Secured");

    }



}
