package jwt.jwtserver.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import jwt.jwtserver.config.auth.PrincipalDetails;
import jwt.jwtserver.model.User;
import lombok.RequiredArgsConstructor;

//login 요청해서 username, password 전송할 때 필터 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;

	//로그인 시도 시 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException {

		//1.username, password 받아서
		//2. 정상인지 로그인 시도 authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출
		//loadUserByUsername()동작
		//4.PrincipalDetails를 세션에 담고 (권한 관리를 위해서)
		//5. JwtToken을 담아서
		System.out.println("AuthenticationFilter 동작 중 ");
		try {
			// BufferedReader reader = request.getReader();
			// String input = null;
			// while((input = reader.readLine())!=null){
			// 	System.out.println(input);
			// }

			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println("user = " + user);
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
				user.getUsername(), user.getPassword());
			//PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
			Authentication authentication = authenticationManager.authenticate(authenticationToken);

			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
			System.out.println("principalDetails = " + principalDetails.getUser().getUsername());

			//authentication 객체가 session 영역에 저장됨 => 로그인이 됨
			return authentication;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		// System.out.println("=======================================");
		// return null;
	}

	//attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
	//JWT 만들어서 request요청한 사용자에게 JWT을 만들어서 리턴
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authResult) throws IOException, ServletException {
		System.out.println("succesfulAuthentication 메서드 실행 중");
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();

		String jwtToken = JWT.create()
			.withSubject(principalDetails.getUsername())
			.withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
			.withClaim("id", principalDetails.getUser().getId())
			.withClaim("username", principalDetails.getUser().getUsername())
			.sign(Algorithm.HMAC512("kimchi"));
		String refreshToken = JWT.create()
			.withSubject("refreshToken")
			.withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 60 * 24)))
			.withClaim("id", principalDetails.getUser().getId())
			.withClaim("username", principalDetails.getUser().getUsername())
			.sign(Algorithm.HMAC512("kimchi"));
		//JWT 생성 후 클라이언트로 JWT 응답
		//클라이언트에서 요청 시 JWT 토큰을 가지고 요청

		response.addHeader("Authorization", "Bearer " + jwtToken);
		response.addCookie(new Cookie("refreshToken", refreshToken));
	}
}



