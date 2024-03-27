package springbootdeveloper.demo.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import springbootdeveloper.demo.domain.RefreshToken;
import springbootdeveloper.demo.repository.RefreshTokenRepository;

@RequiredArgsConstructor
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshToken findByRefreshToken(String refreshToken) {
        return refreshTokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Unexpected token"));
    }
}
