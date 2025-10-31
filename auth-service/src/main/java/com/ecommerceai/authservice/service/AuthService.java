package com.ecommerceai.authservice.service;

import com.ecommerceai.authservice.dto.request.*;
import com.ecommerceai.authservice.dto.response.AuthResponse;
import com.ecommerceai.authservice.dto.response.MessageResponse;
import com.ecommerceai.authservice.dto.response.UserResponse;
import com.ecommerceai.authservice.exception.AuthException;
import com.ecommerceai.authservice.exception.ResourceNotFoundException;
import com.ecommerceai.authservice.mapper.UserMapper;
import com.ecommerceai.authservice.model.RefreshToken;
import com.ecommerceai.authservice.model.Role;
import com.ecommerceai.authservice.model.User;
import com.ecommerceai.authservice.repository.RefreshTokenRepository;
import com.ecommerceai.authservice.repository.UserRepository;
import com.ecommerceai.authservice.security.JwtTokenProvider;
import com.ecommerceai.authservice.security.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;
    private final EmailService emailService;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION = 30 * 60 * 1000; // 30 minutos

    @Transactional
    public AuthResponse register(RegisterRequest request) throws AuthException {
        log.info("Registering new user with email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AuthException("Email already registered");
        }

        User user = User.builder()
                .email(request.getEmail().toLowerCase())
                .password(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName())
                .phoneNumber(request.getPhoneNumber())
                .enabled(true)
                .accountNonLocked(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .emailVerified(false)
                .failedLoginAttempts(0)
                .build();

        user.addRole(Role.ROLE_USER);

        // Gera token de verificação de email
        String verificationToken = UUID.randomUUID().toString();
        user.setEmailVerificationToken(verificationToken);
        user.setEmailVerificationTokenExpiry(LocalDateTime.now().plusHours(24));

        user = userRepository.save(user);

        // Envia email de verificação (async)
        emailService.sendVerificationEmail(user.getEmail(), user.getFullName(), verificationToken);

        log.info("User registered successfully: {}", user.getEmail());

        // Faz login automático após registro
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                UserDetailsImpl.build(user),
                null,
                UserDetailsImpl.build(user).getAuthorities()
        );

        return generateAuthResponse(authentication, null);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) throws AuthException {
        log.info("Login attempt for email: {}", request.getEmail());

        User user = userRepository.findByEmailAndDeletedFalse(request.getEmail().toLowerCase())
                .orElseThrow(() -> new AuthException("Invalid email or password"));

        // Verifica se a conta está bloqueada
        if (!user.getAccountNonLocked()) {
            if (user.getLockTime() != null &&
                    LocalDateTime.now().isBefore(user.getLockTime().plusMinutes(30))) {
                throw new LockedException("Account is locked. Try again later.");
            } else {
                // Desbloqueia a conta após o tempo de bloqueio
                unlockAccount(user);
            }
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail().toLowerCase(),
                            request.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Reset failed attempts
            if (user.getFailedLoginAttempts() > 0) {
                userRepository.updateFailedLoginAttempts(user.getId(), 0);
            }

            // Atualiza último login
            String ipAddress = "127.0.0.1"; // TODO: obter IP real do request
            userRepository.updateLastLogin(user.getId(), LocalDateTime.now(), ipAddress);

            AuthResponse response = generateAuthResponse(authentication, request.getDeviceInfo());

            log.info("User logged in successfully: {}", request.getEmail());
            return response;

        } catch (BadCredentialsException e) {
            handleFailedLogin(user);
            throw new AuthException("Invalid email or password");
        }
    }

    @Transactional
    public AuthResponse refreshToken(String refreshTokenStr) throws AuthException {
        log.info("Refreshing token");

        RefreshToken refreshToken = refreshTokenRepository.findByTokenAndRevokedFalse(refreshTokenStr)
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (refreshToken.isExpired()) {
            refreshTokenRepository.delete(refreshToken);
            throw new AuthException("Refresh token expired");
        }

        User user = refreshToken.getUser();
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        String newAccessToken = tokenProvider.generateAccessToken(authentication);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshTokenStr)
                .tokenType("Bearer")
                .expiresIn(tokenProvider.getExpirationMs() / 1000)
                .user(userMapper.toUserResponse(user))
                .build();
    }

    @Transactional
    public void logout(String token) {
        try {
            UUID userId = tokenProvider.getUserIdFromToken(token);
            refreshTokenRepository.revokeAllUserTokens(userId, LocalDateTime.now());
            log.info("User logged out successfully: {}", userId);
        } catch (Exception e) {
            log.error("Error during logout", e);
        }
    }

    @Transactional(readOnly = true)
    public UserResponse getCurrentUser() throws AuthException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthException("User not authenticated");
        }

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        User user = userRepository.findById(userDetails.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        return userMapper.toUserResponse(user);
    }

    @Transactional
    public MessageResponse requestPasswordReset(PasswordResetRequest request) {
        User user = userRepository.findByEmailAndDeletedFalse(request.getEmail().toLowerCase())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        String resetToken = UUID.randomUUID().toString();
        user.setPasswordResetToken(resetToken);
        user.setPasswordResetTokenExpiry(LocalDateTime.now().plusHours(1));

        userRepository.save(user);

        emailService.sendPasswordResetEmail(user.getEmail(), user.getFullName(), resetToken);

        log.info("Password reset requested for: {}", request.getEmail());

        return MessageResponse.of("Password reset link sent to your email");
    }

    @Transactional
    public MessageResponse confirmPasswordReset(PasswordResetConfirmRequest request) throws AuthException {
        User user = userRepository.findByPasswordResetToken(request.getToken())
                .orElseThrow(() -> new AuthException("Invalid or expired reset token"));

        if (user.getPasswordResetTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new AuthException("Reset token has expired");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        user.setFailedLoginAttempts(0);
        user.setAccountNonLocked(true);
        user.setLockTime(null);

        userRepository.save(user);

        // Revoga todos os refresh tokens
        refreshTokenRepository.revokeAllUserTokens(user.getId(), LocalDateTime.now());

        log.info("Password reset successfully for: {}", user.getEmail());

        return MessageResponse.of("Password reset successfully");
    }

    @Transactional
    public MessageResponse changePassword(ChangePasswordRequest request) throws AuthException {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();

        User user = userRepository.findById(userDetails.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new AuthException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Revoga todos os refresh tokens
        refreshTokenRepository.revokeAllUserTokens(user.getId(), LocalDateTime.now());

        log.info("Password changed successfully for: {}", user.getEmail());

        return MessageResponse.of("Password changed successfully");
    }

    @Transactional
    public MessageResponse verifyEmail(String token) throws AuthException {
        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new AuthException("Invalid verification token"));

        if (user.getEmailVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new AuthException("Verification token has expired");
        }

        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationTokenExpiry(null);

        userRepository.save(user);

        log.info("Email verified successfully for: {}", user.getEmail());

        return MessageResponse.of("Email verified successfully");
    }

    @Transactional
    public MessageResponse resendVerificationEmail() throws AuthException {
        UserDetailsImpl userDetails = (UserDetailsImpl) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();

        User user = userRepository.findById(userDetails.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (user.getEmailVerified()) {
            throw new AuthException("Email already verified");
        }

        String verificationToken = UUID.randomUUID().toString();
        user.setEmailVerificationToken(verificationToken);
        user.setEmailVerificationTokenExpiry(LocalDateTime.now().plusHours(24));

        userRepository.save(user);

        emailService.sendVerificationEmail(user.getEmail(), user.getFullName(), verificationToken);

        log.info("Verification email resent to: {}", user.getEmail());

        return MessageResponse.of("Verification email sent");
    }

    // ===== Helper Methods =====

    private AuthResponse generateAuthResponse(Authentication authentication, String deviceInfo) {
        String accessToken = tokenProvider.generateAccessToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String refreshTokenStr = tokenProvider.generateRefreshToken(userDetails.getId());

        User user = userRepository.findById(userDetails.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        RefreshToken refreshToken = RefreshToken.builder()
                .token(refreshTokenStr)
                .user(user)
                .expiryDate(LocalDateTime.now().plusSeconds(tokenProvider.getRefreshExpirationMs() / 1000))
                .deviceInfo(deviceInfo)
                .ipAddress("127.0.0.1") // TODO: obter IP real
                .build();

        refreshTokenRepository.save(refreshToken);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenStr)
                .tokenType("Bearer")
                .expiresIn(tokenProvider.getExpirationMs() / 1000)
                .user(userMapper.toUserResponse(user))
                .build();
    }

    private void handleFailedLogin(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        userRepository.updateFailedLoginAttempts(user.getId(), attempts);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            userRepository.lockUser(user.getId(), false, LocalDateTime.now());
            log.warn("Account locked due to too many failed login attempts: {}", user.getEmail());
        }
    }

    private void unlockAccount(User user) {
        userRepository.lockUser(user.getId(), true, null);
        userRepository.updateFailedLoginAttempts(user.getId(), 0);
        log.info("Account unlocked: {}", user.getEmail());
    }
}
