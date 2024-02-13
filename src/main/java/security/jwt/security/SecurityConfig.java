package security.jwt.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import security.jwt.jwt.JwtAuthenticationFilter;
import security.jwt.security.auth.PrincipalDetailsService;
import security.jwt.security.oauth.handler.OAuth2AuthenticationSuccessHandler;
import security.jwt.security.oauth.service.CustomOauth2UserService;
import security.jwt.util.TokenUtil;

/**
 * Google OAUTH 1. 코드받기 (인증), 2. 액세스 토큰(권한) 3. 사용자 프로필 정보 가져오고, 4-1. 그 정보를 토대로 회원가입을 자동으로 진행
 * 4-2.(이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점몰 -> (vip등급, 일반등급)
 */

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final PrincipalDetailsService principalDetailsService;
    private final TokenUtil tokenUtil;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomOauth2UserService customOauth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Bean
    public static BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(
                authorize -> authorize
                    .requestMatchers("/user/**").authenticated() // 로그인 요청
                    .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN") // 권한 검증
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().permitAll()
            )
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(customAuthenticationEntryPoint)
                .accessDeniedPage("/errors-access-denied")
            );

        http
//            .formLogin(form -> form
//                .loginPage("/loginForm")
//                .loginProcessingUrl("/login") // login 주소가 호출이 되면 Security가 낚아채서 대신 로그인을 진행
//                .defaultSuccessUrl("/")) // 특정 페이지 요청 시 그 페이지로 연결해줌
            .oauth2Login(
                (oauth2Login) -> oauth2Login
//                    .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리가 필요 | Tip. 코드X (액세스토큰 + 사용자 프로필정보를 받음)
                    .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.baseUri("/login"))
                    .redirectionEndpoint(redirectEndpoint ->
                        redirectEndpoint.baseUri("/login/oauth2/code/*"))
                    .userInfoEndpoint(userInfo -> userInfo
                        .userService(customOauth2UserService)) // 사용자 정보 엔드포인트를 처리하는 사용자 서비스 설정
                    .successHandler(oAuth2AuthenticationSuccessHandler)
            );

        http
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(customAuthenticationFilter(), JwtAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOriginPattern("*");
        config.addExposedHeader("Authorization");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter() throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(
            authenticationManager());
        customAuthenticationFilter.afterPropertiesSet();
        return customAuthenticationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider(principalDetailsService, bCryptPasswordEncoder());
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(tokenUtil);
    }
}
