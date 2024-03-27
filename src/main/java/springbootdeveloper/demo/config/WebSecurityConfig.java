/*
package springbootdeveloper.demo.config;
import lombok.Builder;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import springbootdeveloper.demo.service.UserDetailService;



import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
*/
/*
    private final UserDetailService userService;

    //스프링 시큐리티 기능 비활성화
    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
                .requestMatchers(toH2Console())
                .requestMatchers("/static/**");
    }*//*


    //특정 http 요청에 대한 웹 기반 보안 구성
   */
/* @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests()
                .requestMatchers("/login", "/signup", "/user").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/articles")
                .and()
                .logout()
                .logoutSuccessUrl("/login")
                .invalidateHttpSession(true)
                .and()
                .csrf().disable()
                .build();
    }*//*



    //위에 메서드체이닝방식을 밑에 람다형 함수로 변환

    */
/*
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests((authorizeRequests) ->
                        authorizeRequests//인증, 인가 설정
                                .requestMatchers("/login", "/signup", "/user").permitAll()
                                .anyRequest().authenticated())

                .formLogin((formLogin) ->
                        formLogin//폼기반 로그인 설정
                                .loginPage("/login")
                                .defaultSuccessUrl("/articles"))
                .logout((logoutConfig) ->
                        logoutConfig
                                .logoutSuccessUrl("/login")
                                .invalidateHttpSession(true))
                .csrf((csrfConfig) ->
                        csrfConfig.disable()
                );
        return http.build();
    }





    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


*//*


}*/
