package com.bkaracan.sampleproject.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  // Bu anotasyon Spring Security yapılandırmasını etkinleştirir.
@EnableMethodSecurity  // Bu anotasyon metot düzeyinde güvenliği (örn. @PreAuthorize) etkinleştirir.
public class SecurityConfig {

    // Parola şifreleme için bir BCryptPasswordEncoder bean'i tarantula.
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // In-memory kullanıcı detay servisini tanımlar.
    // Bu örnek için iki kullanıcı (user1 ve admin) oluşturulur.
    @Bean
    public UserDetailsService users() {
        UserDetails user1 = User.builder()
                .username("ahukaracan")
                .password("ahu123!")  // Dikkat: Gerçek uygulamalarda şifrelerin şifrelenmesi gerekir!
                .roles("USER")  // Kullanıcıya "USER" rolü atanır.
                .build();

        UserDetails admin = User.builder()
                .username("bkaracan")
                .password("burak123!")  // Dikkat: Gerçek uygulamalarda şifrelerin şifrelenmesi gerekir!
                .roles("ADMIN")  // Kullanıcıya "ADMIN" rolü atanır.
                .build();

        return new InMemoryUserDetailsManager(user1, admin);
    }

    // HTTP güvenlik yapılandırmasını tanımlar.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
        security
                .headers(x -> x.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))  // Frame seçeneklerini devre dışı bırakır.
                .csrf(AbstractHttpConfigurer::disable)  // CSRF korumasını devre dışı bırakır.
                .formLogin(AbstractHttpConfigurer::disable)  // Form tabanlı girişi devre dışı bırakır.
                .authorizeHttpRequests(x -> x.requestMatchers("/public/**", "/auth/**").permitAll())  // "/public" ve "/auth" yollarına herkesin erişimine izin verir.
                .authorizeHttpRequests(x -> x.anyRequest().authenticated())  // Diğer tüm istekler için kimlik doğrulaması gerektirir.
                .httpBasic(Customizer.withDefaults());  // HTTP Basic kimlik doğrulamasını kullanır.

        return security.build();
    }
}
