package com.faithabiola.Security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component //To make the class a spring bean
@RequiredArgsConstructor // To generate a constructor with parameters for all final fields or all fields marked with the @NonNull
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;// Create a bean of type userDetailsService or create a class that implements this interface and give it a service or component annotation so that it becomes a managed bean and spring will be able to inject it
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization"); //Because JWT authentication token needs to be passed within the header called Authorization(which contains the JWT token)
        final String jwt;
        final String userEmail;
        // Implement the authHeader to check the JWT token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) { // The bearer token should always start with the keyword Bearer
            filterChain.doFilter(request, response);
            return;
        }
        // Extract the token from the authHeader
        jwt = authHeader.substring(7); //Position 7 because Bearer plus the space are 7 characters

        // Extract the user email from JWT token
        userEmail = jwtService.extractUsername(jwt);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {// to check if the user is already authenticated or not. If the getAuthentication is null it means the user is not authenticated
            //After that we need to get the user from the database, by creating an object called userDetails
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            //Next step is to validate and check if the token is still valid
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // if the token is valid , update the security context and send the request to the dispatcher servlet, then create an object of type username password authentication token
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // this is null because the user does not have credentials
                        userDetails.getAuthorities()
                ); // it is needed by the security context holder in order to update the security context
                //After instantiating the usernameAuthenticationToken, give it more details by using auth token
                authToken.setDetails(// extend the auth token with the details of the request
                        new WebAuthenticationDetailsSource().buildDetails(request) // Then build the details out of the HTTP request of
                );
                //Final step is to update the auth token using security context holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response); // after the if statement always call the filterchain to pass the hand to the next filter to be executed
    }
}

// AFTER THIS PROCESS, TELL SPRING WHICH CONFIGURATION TO BE USED IN ORDER TO MAKE ALL THIS WORK, WE NEED TO BIND, THE FILTER NEEDS TO BE USED BY CREATING A NEW CONFIGURATION CLASS
