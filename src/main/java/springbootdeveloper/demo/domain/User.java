package springbootdeveloper.demo.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Entity
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false)
    private Long id;

    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Transient
    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "nickname",unique = true)
    private String nickname;

    @Builder
    public User(String email, String password, String auth, String nickname) {
        this.email = email;
        this.password = password;
        this.nickname = nickname;

    }

    public User update(String nickname) {
        this.nickname = nickname;

        return this;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("user"));
    }
    //사용자의 ID를 반환(고유한한값)
    @Override
    public String getUsername() {
        return email;
    }
    //사용자의 패스워드 반환
    @Override
    public String getPassword() {
        return password;
    }
    //계정만료 여부 반환
    @Override
    public boolean isAccountNonExpired() {
        //만료되었는지 확인하는 로직
        return true; // -> 만료되지 않았음
    }

    //계정잠금여부 반환
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    //패스워드의 만료여부 반환
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    //계정사용가능여부 반환
    @Override
    public boolean isEnabled() {
        return true;
    }

}
