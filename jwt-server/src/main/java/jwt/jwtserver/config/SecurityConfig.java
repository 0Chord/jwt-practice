package jwt.jwtserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import jwt.jwtserver.config.jwt.JwtAuthenticationFilter;
import jwt.jwtserver.config.jwt.JwtAuthorizationFilter;
import jwt.jwtserver.filter.MyFilter1;
import jwt.jwtserver.filter.MyFilter3;
import jwt.jwtserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CorsFilter corsFilter;
	private final UserRepository userRepository;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
		http.csrf()
			.disable()
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilter(corsFilter)
			.formLogin()
			.disable()
			.httpBasic()
			.disable()
			.addFilter(new JwtAuthenticationFilter(authenticationManager()))//AuthenticationManager
			.addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository))
			.authorizeRequests()
			.antMatchers("/api/v1/user/**")
			.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			.antMatchers("/api/v1/manager/**")
			.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			.antMatchers("/api/v1/admin/**")
			.access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll();
	}
}
