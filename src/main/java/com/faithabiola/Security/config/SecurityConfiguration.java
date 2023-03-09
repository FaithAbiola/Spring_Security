package com.faithabiola.Security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity //The two annotations need to be together when working with springboot 3.0
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter; // Make it final so that it will be automatically injected by spring
    private final AuthenticationProvider authenticationProvider;

    // When the application starts spring security starts will try to look for a bean of type securityfilterchain, which is responsible for configuring all the HTTP security of the application
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //Start configuring the HTTP security
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()// Within the security we can choose what URLs and pathways we want to secure, but we can have whitelist, which means that some endpoints do not require any authentication or token, like creating an account and logging in
                .requestMatchers("/api/v1/auth/**") // It will take a list of patterns to represent the application(the ** is used to authorize all the methods within the controller, this is used because there are no business logics in this controller)
                .permitAll() // To permit all the request in the list
                .anyRequest()// All the other requests to be authenticated and the list in the requestMatchers should be whitelisted, to authorize all the requests in the list
                .authenticated()
                .and()// To configure the session management means what we said that when we implemented the filter we want a once per request filter means every request should be authenticated this means that we should not store the authentication State or the session State should not be stored so the session should be stateless and this will help us ensure that each request should be authenticated
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)// Spring will create a new session for each request
                .and() // To tell spring which authentication provider to use
                .authenticationProvider(authenticationProvider)// Then use the JWT filter creates
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); //before is used to execute the filter before the filter calls the username and password authentication

        return http.build(); //add an exception because the build might throw an exception
    }
}
