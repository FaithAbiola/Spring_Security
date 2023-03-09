package com.faithabiola.Security.auth;

import com.faithabiola.Security.Role;
import com.faithabiola.Security.User;
import com.faithabiola.Security.UserRepository;
import com.faithabiola.Security.config.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService; // To generate the token using the user object created
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) { // The register method will allow creation of user, save it to the database and return the generated token
        //Create a user object of out of the register request
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // password needs to be encoded before saving it to the database by injecting the password encoder service
                .role(Role.USER) //make a static role
                .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);//Create a new variable to return the authentication response that contains the token, the JWT service needs to be injected to generate the token
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())// This will only execute if there was no error and the user has been authenticated
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);//Create a new variable to return the authentication response that contains the token, the JWT service needs to be injected to generate the token
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}

