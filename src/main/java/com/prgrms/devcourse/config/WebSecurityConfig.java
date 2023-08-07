package com.prgrms.devcourse.config;

import com.prgrms.devcourse.user.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import javax.sql.DataSource;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import static org.springframework.security.authorization.AuthenticatedAuthorizationManager.fullyAuthenticated;
import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;
import static org.springframework.security.authorization.AuthorizationManagers.allOf;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);

    private final UserService userService;

    public WebSecurityConfig(UserService userService) {
        this.userService = userService;
    }

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(antMatcher("/assets/**"), antMatcher("/h2-console/**"));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*@Bean
    UserDetailsService userDetailsService(DataSource dataSource) {
        var jdbcDao = new JdbcDaoImpl();
        jdbcDao.setDataSource(dataSource);
        return jdbcDao;
    }*/

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        /**
         * spring security user 추가
         */

        AuthenticationManagerBuilder auth = http.getSharedObject(AuthenticationManagerBuilder.class);
        auth.userDetailsService(userService);

//        AuthenticationManagerBuilder auth = http.getSharedObject(AuthenticationManagerBuilder.class);
//        auth.inMemoryAuthentication().
//                withUser("user").password("{noop}1234").roles("USER")
//                .and()
//                .withUser("admin1").password("{noop}1234").roles("ADMIN")
//                .and()
//                .withUser("admin2").password("{noop}1234").roles("ADMIN");

        http
                /**
                 * 권한 추가
                 */
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(antMatcher("/assets/**"), antMatcher("/h2-console/**"))
                        .permitAll()
                        .requestMatchers(antMatcher("/me")).access(new HierarchyBasedAuthorizationManager(roleHierarchy()))//hasAnyRole("USER", "ADMIN")
                        .requestMatchers(antMatcher("/admin")).access(allOf(hasRole("ADMIN"), fullyAuthenticated(), new CustomAuthorizationManager()))
                        .anyRequest().permitAll())
                /**
                 * 로그인 추가
                 */
                .formLogin((formLogin) -> formLogin
                        .defaultSuccessUrl("/")
                        .usernameParameter("username")
                        .passwordParameter("password")//html 로그인 페이지에 username, pawssword에 해당하는 파라미터 값(아이디랑 비밀번호)
                        .permitAll()
                )
                /**
                 * 로그아웃 추가
                 */
                .logout((logout) -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("remember-me")
                )
                /**
                 * 아이디 비번 쿠키 기반 기억하기
                 */
                .rememberMe((rememberMe) -> rememberMe
                        .key("my-remember-me")
                        .rememberMeParameter("remember-me")//html 로그인 페이지에 name에 해당하는 파라미터 값
                        .tokenValiditySeconds(300))// 쿠키 기반
                /**
                 * http 요청을 https로 리다이렉트
                 * ChannelProcessingFilter
                 */
                .requiresChannel((requiresChannel) -> requiresChannel
                        .anyRequest().requiresSecure()
                )
                /**
                 * 익명 사용자 추가
                 * AnonymousAuthenticationFilter
                 */
                .anonymous((anonymous) -> anonymous
                        .principal("thisIsAnonymousUser")
                        .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
                )
                .exceptionHandling((exceptionHandling) -> exceptionHandling
                        .accessDeniedHandler(accessDeniedHandler())
                )
                .sessionManagement((sessionManagement -> sessionManagement
                        .sessionFixation().changeSessionId()
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .invalidSessionUrl("/")
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                ));
        return http.build();
    }// 이것도 마찬가지로 변경 됏음. 과거 사용했던 메소드 밑에 현재 버전에 맞는 메소드가 있음.

    @Bean
    AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("### Access Denied ###");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }// 접근 거부 핸들러

    static class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
        private static final Pattern PATTERN = Pattern.compile("[0-9]+$");

        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
            var user = (User) authentication.get().getPrincipal();
            var userName = user.getUsername();
            var matcher = PATTERN.matcher(userName);
            if (matcher.find()) {
                var num = Integer.parseInt(matcher.group());
                if (num % 2 == 0) {
                    return new AuthorizationDecision(true);
                }
            }
            return new AuthorizationDecision(false);
        }
    }/*
     커스텀 권한 매니저 -> Spring security 6버전이 되면서 filterSecurityInterceptor가 deprecated 됏음.
     새로운 간소화된 AuthorizationManager API와 AuthorizationFilter를 사용하도록 변경 됏음. 그래서 커스텀 할때는
     AuthorizationManager를 상속받아서 사용하면 됨 대충 위와 같고 더 자세히 알고 싶으면 대표적인 구현체인 WebExpressionAuthorizationManager를 참고하면 됨.
    */

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }/*
       계층형 권한 설정 스프링 시큐리티 버전 6.0에 추가된 내용.
       계층형 권한 설정을 통해 ROLE_ADMIN이 ROLE_USER보다 상위 권한이라는 것을 설정함.
     */


    static class HierarchyBasedAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

        private final RoleHierarchy roleHierarchy;

        public HierarchyBasedAuthorizationManager(RoleHierarchy roleHierarchy) {
            this.roleHierarchy = roleHierarchy;
        }

        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
            var userAuthorities = authentication.get().getAuthorities();
            var reachableAuthorities = roleHierarchy.getReachableGrantedAuthorities(userAuthorities);

            var hasUserRole = reachableAuthorities.stream()
                    .anyMatch(auth -> "ROLE_USER".equals(auth.getAuthority()));

            return new AuthorizationDecision(hasUserRole);
        }
    }
}