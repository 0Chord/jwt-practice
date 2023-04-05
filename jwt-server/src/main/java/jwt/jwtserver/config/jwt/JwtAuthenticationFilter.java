package jwt.jwtserver.config.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
		return super.attemptAuthentication(request, response);
	}
}



