package com.alterra.demorbac.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.alterra.demorbac.dto.PingResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;


@RestController
@RequestMapping("/v1/user")
public class UserController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping(value="/admin")
    public ResponseEntity<Object> adminPing() {
        return ResponseEntity.ok().body(PingResponse.builder()
                .message("Only admin can view this resource!")
                .build());
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping(value="/user")
    public ResponseEntity<Object> userPing() {
        return ResponseEntity.ok().body(PingResponse.builder()
                .message("Any user can view this resource!")
                .build());
    }
    
    
}
