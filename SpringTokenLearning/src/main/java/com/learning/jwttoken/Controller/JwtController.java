package com.learning.jwttoken.Controller;

import com.learning.jwttoken.Service.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RequestMapping("/api/jwts")
@RestController
@RequiredArgsConstructor
public class JwtController {

    private final JwtService jwtService;

    @GetMapping("/loginUser")
    public String loginUser(){
        System.out.println("loginUser");
        return "loginUser";
    }

    @GetMapping("/secure-data")
    public String secureData(){
        return "secure-data";
    }

    @PostMapping("/refreshToken")
    public Map<String,String> refreshToken(HttpServletRequest request, HttpServletResponse response){

       // System.out.println("refreshToken 1 :  " + refreshToken);
//@RequestHeader("refreshToken") String refreshToken,
         String refreshJwtToken=null;
         for (Cookie cookie : request.getCookies())
         {
             System.out.println(cookie.getName());
             if ("refreshToken".equals(cookie.getName()))
             {
                 refreshJwtToken = cookie.getValue();
               System.out.println("refreshToken "+refreshJwtToken);
             }
         }
        Claims claims = jwtService.validateRefreshToken(refreshJwtToken);
        String userName = claims.get("username", String.class);
        String roles = claims.get("roles", String.class);

        String accessToken = jwtService.generateJwtToken(userName, roles);

        response.setHeader("Authorization", "Bearer " + accessToken);

        return Map.of("accessToken",accessToken);
    }

    @GetMapping("/validateToken")
    public String validateToken(){
        return "validateToken";
    }
}
