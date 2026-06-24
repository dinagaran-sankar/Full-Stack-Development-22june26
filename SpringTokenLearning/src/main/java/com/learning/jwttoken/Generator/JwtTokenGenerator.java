package com.learning.jwttoken.Generator;

import com.learning.jwttoken.Constant.ApplicationConstant;
import com.learning.jwttoken.Service.JwtService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtTokenGenerator extends OncePerRequestFilter {

   //private final Environment environment;

   private final JwtService jwtService;

//    public String generateToken(Authentication authentication){
//
//
//    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {

//        SecretKey decodeKeys = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretKey));
//        System.out.println("decode secret keys : " +decodeKeys);

//            SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));
//            System.out.println(secretKey.getEncoded());
            //User user = (User) authentication.getPrincipal();

            String userName = authentication.getName();
            String roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));

            String jwtToken = jwtService.generateJwtToken (userName,roles);
            String refreshToken = jwtService.generateRefreshToken(userName,roles);

            response.setHeader("Authorization", "Bearer " + jwtToken);
            //response.setHeader("X-Refresh-Token", refreshToken);

            //production ready cookies
            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setMaxAge(7*24*60*60);
            refreshTokenCookie.setPath("/api/jwts/refreshToken");
            response.addCookie(refreshTokenCookie);
        }

        else {
            System.out.println("Authentication object is null");
        }
        filterChain.doFilter(request, response);
    }

    //Skip filter for ALL endpoints EXCEPT loginUser
    //Only login API is public; everything else must pass through JWT filter.
    //Skip filter ONLY for:
    //login ✅//refresh
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        return !request.getServletPath().equals("/api/jwts/loginUser") && !request.getServletPath().equals("/api/jwts/refreshToken");
    }
}
