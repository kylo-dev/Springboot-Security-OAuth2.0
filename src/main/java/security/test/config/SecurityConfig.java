package security.test.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import security.test.config.oauth.PrincipalOauth2UserService;

/**
 * Google OAUTH
 * 1. 코드받기 (인증), 2. 액세스 토큰(권한)
 * 3. 사용자 프로필 정보 가져오고, 4-1. 그 정보를 토대로 회원가입을 자동으로 진행
 * 4-2. (이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점몰 -> (vip등급, 일반등급)
 */

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        authorize -> authorize
                                .requestMatchers("/user/**").authenticated()
                                .requestMatchers("/manager/**").hasAnyRole("MANAGER","ADMIN")
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                .anyRequest().permitAll()
                )
                .formLogin(form -> form
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login") // login 주소가 호출이 되면 Security가 낚아채서 대신 로그인을 진행
                        .defaultSuccessUrl("/")); // 특정 페이지 요청 시 그 페이지로 연결해줌
//                .csrf().disable()
//                .authorizeHttpRequests()
//                .antMatchers("/user/**").authenticated()
//                .antMatchers("/manager/**").hasAnyRole("MANAGER","ADMIN")
//                .antMatchers("/admin/**").hasRole("ADMIN")
//                .anyRequest().permitAll()
//                .and()
//                .formLogin()
//                .loginPage("/loginForm")
//                .loginProcessingUrl("/login") // login 주소가 호출이 되면 Security가 낚아채서 대신 로그인을 진행
//                .defaultSuccessUrl("/")
//                .and()
//                .oauth2Login()
//                .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리가 필요/ Tip. 코드X (액세스토큰 + 사용자 프로필정보 O)
//                .userInfoEndpoint()
//                .userService(principalOauth2UserService);

        return http.build();
    }

}
