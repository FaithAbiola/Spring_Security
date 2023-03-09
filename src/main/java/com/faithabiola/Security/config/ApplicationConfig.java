package com.faithabiola.Security.config;

import com.faithabiola.Security.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor // it is used incase I want to inject something
public class ApplicationConfig {// Annotate with configuration to make the class a configuration so that spring will pick up the class to implement and inject all the beans that we will declare in the applicationconfig

    //Fetch the user or to get the user from the database, by injecting the user repository
    private final UserRepository userRepository;

    // Create a bean of type user details service
    @Bean // To indicate to Spring that this method represents a bean and it is always public
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() { // It is the data access object responsible to fetch the user details and encode password
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(); //Specify two properties
        authProvider.setUserDetailsService(userDetailsService());//tell the auth provider which user details to use in order to fetch information about the user
        authProvider.setPasswordEncoder(passwordEncoder());// provide the password encoder that will be used in the application
        return authProvider;

    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception { // Authentication configuration holds information about the authentication manager
        return config.getAuthenticationManager();
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
//Authentication manager has methods that allows authentication of user using username and password
}
//The endpoints where the user can create an account and can also authenticate