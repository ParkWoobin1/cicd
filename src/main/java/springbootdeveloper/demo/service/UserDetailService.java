package springbootdeveloper.demo.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import springbootdeveloper.demo.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserDetailService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException((email)));
    }
}
