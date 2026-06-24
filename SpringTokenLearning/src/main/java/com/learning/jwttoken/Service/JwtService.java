package com.learning.jwttoken.Service;

import com.learning.jwttoken.Constant.ApplicationConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtService {

    private final Environment environment;

    private SecretKey getSecretKey() {
        String jwtSecretKey = environment.getProperty(ApplicationConstant.SECRET_KEY,
                ApplicationConstant.SECRET_VALUE);
        return Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));
    }

    private SecretKey getRefreshKey() {
        String refreshSecretKey = environment.getProperty(ApplicationConstant.REFRESH_SECRET_KEY,
                ApplicationConstant.REFRESH_SECRET_VALUE);

        return Keys.hmacShaKeyFor(refreshSecretKey.getBytes(StandardCharsets.UTF_8));
    }


    public String generateJwtToken(String username, String roles){

       return Jwts.builder().issuer("Nelli Food Products")
                .subject("Jwt Token")
                .claim("username", username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1 * 60 * 1000))
                .signWith(getSecretKey()).compact();
    }

    public String generateRefreshToken(String username,String roles){
        return  Jwts.builder().issuer("Nelli Food Product - Refresh Token")
                .subject("Refresh Token")
                .claim("username",username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+7*24*60*60*1000))
                .signWith(getRefreshKey())
                .compact();
    }

    public Claims validateRefreshToken(String jwtValidateRefreshToken) {
        Claims claims = null;
        try {
            if (jwtValidateRefreshToken != null) {
                String refreshTokenSecretKey = environment.getProperty(ApplicationConstant.REFRESH_SECRET_KEY
                        , ApplicationConstant.REFRESH_SECRET_VALUE);

                SecretKey refreshSecretKey = Keys.hmacShaKeyFor(refreshTokenSecretKey.getBytes(StandardCharsets.UTF_8));

                claims = Jwts.parser().verifyWith(refreshSecretKey).build()
                        .parseClaimsJws(jwtValidateRefreshToken).getPayload();
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return claims;
    }

}
