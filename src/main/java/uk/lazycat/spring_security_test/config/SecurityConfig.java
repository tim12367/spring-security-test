package uk.lazycat.spring_security_test.config;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
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

		// 設定oauth2.0
		http.oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(withDefaults()));

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {
		UserDetails user = User.withUsername("user")
				.password("dummy")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				.roles("USER")
				.build();

		UserDetails admin = User.withUsername("admin")
				.password("dummy")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				.roles("ADMIN")
				.build();

		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return jdbcUserDetailsManager;
	}

	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(); // 預設10
	}
}
