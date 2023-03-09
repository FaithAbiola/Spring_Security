package com.faithabiola.Security.auth;
// It will have two endpoints that will allow a user to create a new account and authenticate an existing user

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController // To make the class a controller
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
//Anything that has to do with getting information from a user, is called postmapping, getmapping is used when fetching information from database and when a user wants to get information from the backend e.g walletbalance
    private final AuthenticationService authenticationService; //To inject it (dependency injection)
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request //It will hold all the registration information
    ) {
       return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request //It will hold all the registration information
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}
