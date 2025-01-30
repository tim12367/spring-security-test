package uk.lazycat.spring_security_test.controller;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {

	@Autowired
	private JwtEncoder jwtEncoder;

	/*
	 * Authentication json結構: { "authorities": [ { "authority": "ROLE_USER" } ],
	 * "details": { "remoteAddress": "0:0:0:0:0:0:0:1", "sessionId": null },
	 * "authenticated": true, "principal": { "password": null, "username": "user",
	 * "authorities": [ { "authority": "ROLE_USER" } ], "accountNonExpired": true,
	 * "accountNonLocked": true, "credentialsNonExpired": true, "enabled": true },
	 * "credentials": null, "name": "user" }
	 */

	@PostMapping("/authenticate")
	public JwtResponse authentication(Authentication authentication) {
		return new JwtResponse(this.createToken(authentication));
	}

	private String createToken(Authentication authentication) {
		Instant now = Instant.now();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer("self")
				.issuedAt(now)
				.expiresAt(now.plusSeconds(60 * 30)) // 30分鐘有效
				.subject(authentication.getName())
				.claim("scope", this.createScope(authentication))
				.build();

		JwtEncoderParameters parameter = JwtEncoderParameters.from(claims);
		return jwtEncoder.encode(parameter).getTokenValue();
	}

	private String createScope(Authentication authentication) {
		return authentication.getAuthorities().stream()
				.map(authority -> authority.getAuthority())
				.collect(Collectors.joining(",")); // 拿出所有角色
	}
}

record JwtResponse(String token) {
}