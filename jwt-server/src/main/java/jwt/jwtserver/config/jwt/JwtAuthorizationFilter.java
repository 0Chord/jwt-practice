package jwt.jwtserver.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import jwt.jwtserver.config.auth.PrincipalDetails;
import jwt.jwtserver.model.User;
import jwt.jwtserver.repository.UserRepository;

//시큐리티가 filter를 가지고 있는데 그 중에 BasicAuthenticationFilter가 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 윗 필터를 무조건 거쳐야함
// 권한이나 인증이 필요없는 주소라면 필터를 안탐
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private final UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws
		IOException,
		ServletException {
		// super.doFilterInternal(request, response, chain);
		System.out.println("인증이나 권한이 필요한 주소 요청됨 ");
		String header = request.getHeader("Authorization");
		System.out.println("header = " + header);

		if (header == null || !header.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}

		String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
		System.out.println("jwtToken = " + jwtToken);
		String username = JWT.require(Algorithm.HMAC512("kimchi"))
			.build()
			.verify(jwtToken)
			.getClaim("username")
			.asString();
		System.out.println("username = " + username);
		if (username != null) {
			User userEntity = userRepository.findByUsername(username);
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			//jwtToken 서명을 통해 서명이 정상이면 authentication 객체를 만들어 줌
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null,
				principalDetails.getAuthorities());
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		chain.doFilter(request, response);
	}
}

