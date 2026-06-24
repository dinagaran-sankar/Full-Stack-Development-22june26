package com.learning.jwttoken.Validator;

import com.learning.jwttoken.Constant.ApplicationConstant;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;

public class JwtTokenValidator extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String jwtValidationToken = request.getHeader("Authorization");

        String jwtValidateRefreshToken = request.getHeader("refreshToken");
        

        try {
            Claims claimsAccessToken = validateAccessToken(jwtValidationToken);

            String username = String.valueOf(claimsAccessToken.get("username"));
            String roles = String.valueOf(claimsAccessToken.get("roles"));
            Date expiration = claimsAccessToken.getExpiration();
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null,
                    AuthorityUtils.commaSeparatedStringToAuthorityList(roles));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        catch (MalformedJwtException e) {
            e.printStackTrace();
        }
        catch (ExpiredJwtException e)
        {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Token is expired.Please refresh token");
            return;
        }
        catch (UnsupportedJwtException e)
        {
            e.printStackTrace();
        }
        catch (IllegalArgumentException e){
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        filterChain.doFilter(request, response);
    }

    private Claims validateAccessToken(String jwtValidationToken) {

        Claims claims = null;
        if (jwtValidationToken != null && jwtValidationToken.startsWith("Bearer ")) {

                String jwtToken = jwtValidationToken.substring("Bearer ".length());
                Environment environment = getEnvironment();
                if (environment != null) {

                    String jwtSecretKey = environment.getProperty(ApplicationConstant.SECRET_KEY, ApplicationConstant.SECRET_VALUE);

                    SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));

                    claims = Jwts.parser()
                            .verifyWith(secretKey)
                            .build().parseClaimsJws(jwtToken).getPayload();
                }

        }
        return claims;
    }



//    Don’t execute this filter for these specific URLs
    //Without this method ❌
//Request → JWT Filter → checks token → fails → never reaches controller
//    With this method ✅
//    Request → check shouldNotFilter()
//       → TRUE → skip filter ✅
//            → controller executes ✅
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/api/jwts/loginUser") || request.getServletPath().equals("/api/jwts/refreshToken");
    }
}
