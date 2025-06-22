package com.bootlabs.resource.controller;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@CrossOrigin(origins = "*")
@RestController
@Slf4j
@RequestMapping("/info")
public class InfoController {

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @GetMapping("/user")
    public List<ApiResponse> getUserInfo(Principal principal, JwtAuthenticationToken jwtToken) {
        List<ApiResponse> response = new ArrayList<>();
        response.add(new ApiResponse("principal", principal.getName()));
        response.add(new ApiResponse("user", jwtToken.getToken()));
        response.add(new ApiResponse("authorities", jwtToken.getAuthorities()));

        return response;
    }
}