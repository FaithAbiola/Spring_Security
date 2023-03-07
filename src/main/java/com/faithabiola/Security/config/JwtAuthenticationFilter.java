package com.faithabiola.Security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
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


        }

    }
}
