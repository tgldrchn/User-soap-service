package com.example.soap.service;

import com.example.soap.model.*;
import com.example.soap.repository.AuthUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private AuthUserRepository repo;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private BCryptPasswordEncoder encoder;

    public RegisterResponse register(RegisterRequest req) {
        RegisterResponse res = new RegisterResponse();

        if (repo.findByUsername(req.getUsername()).isPresent()) {
            res.setSuccess(false);
            res.setMessage("Username already exists");
            return res;
        }

        AuthUser user = new AuthUser();
        user.setUsername(req.getUsername());
        user.setPasswordHash(encoder.encode(req.getPassword()));
        user.setRole("USER");
        repo.save(user);

        res.setSuccess(true);
        res.setUserId(user.getId());
        res.setMessage("Registered successfully");
        return res;
    }

    public LoginResponse login(LoginRequest req) {
        LoginResponse res = new LoginResponse();

        Optional<AuthUser> userOpt = repo.findByUsername(req.getUsername());

        if (userOpt.isEmpty() ||
            !encoder.matches(req.getPassword(), userOpt.get().getPasswordHash())) {
            res.setMessage("Invalid credentials");
            return res;
        }

        AuthUser user = userOpt.get();

       
        String token = jwtUtil.generateToken(user.getId(), user.getUsername(), user.getRole());

        res.setToken(token);
        res.setUserId(user.getId());
        res.setRole(user.getRole());
        res.setMessage("Login successful");
        return res;
    }

    public ValidateTokenResponse validateToken(ValidateTokenRequest req) {
        ValidateTokenResponse res = new ValidateTokenResponse();

        try {
            String token = req.getToken().trim();
            String userId = jwtUtil.validateAndGetUserId(token);
            String role = jwtUtil.getRoleFromToken(token);

            res.setValid(true);
            res.setUserId(userId);
            res.setRole(role); 

        } catch (Exception e) {
            res.setValid(false);
            res.setUserId(null);
            res.setRole(null);
        }

        return res;
    }
}