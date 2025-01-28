package uk.lazycat.spring_security_test.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// 驗證所有請求
		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());

		// 預設登入登出頁面
//		http.formLogin(withDefaults()); 

		// 使用stateless不建立session
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		// 使用 basic authentication 驗證
		http.httpBasic(withDefaults());

		// csrf 停用
		http.csrf(csrf -> csrf.disable());

		// <frame>啟用
		http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withUsername("user")
				.password("{noop}dummy")
				.roles("USER")
				.build();

		UserDetails admin = User.withUsername("admin")
				.password("{noop}dummy")
				.roles("ADMIN")
				.build();

		return new InMemoryUserDetailsManager(user, admin);
	}
}
