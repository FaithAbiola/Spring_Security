package com.faithabiola.Security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY= "655468576D5A7134743777217A25432A46294A404E635266556A586E32723575";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //Implement another method which can extract a single claim that is passed
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {//generate token using userdetails
        return generateToken(new HashMap<>(), userDetails);
    }
    public String generateToken( //generate token using extraclaims and user details
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) //Token will be valid for 24hours + 1000milliseconds
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // The key to use to sign in the token
                .compact(); //compact will generate and return the token
    }

    public boolean  isTokenValid(String token, UserDetails userDetails) { // It's taking two parameters because we want to validate if the token belongs to the user
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token); // To make sure that username within the token is same with the username we have as input
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());//To make sure it's before that day's date
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) //signing key is used to digitally sign the JWT, it is used to create the signature part of the JWT which is used to verify that the sender of the JWT is who it claims to be and ensure that the message wasn't changed
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
//Claims are statements about an entity (user and additional data)
//Registered, Public and Private claims
