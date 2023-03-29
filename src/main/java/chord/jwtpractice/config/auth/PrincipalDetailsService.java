package chord.jwtpractice.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import chord.jwtpractice.model.User;
import chord.jwtpractice.repository.UserRepository;
import lombok.RequiredArgsConstructor;

// 시큐리티 설정에서 loginProcessingUrl("/login");
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수가 실
@Service

public class PrincipalDetailsService implements UserDetailsService {

	@Autowired
	UserRepository userRepository;

	// 시큐리티 세션 => Authentication(내부 UserDetails)
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUsername(username);
		if (userEntity != null) {
			return new PrincipalDetails(userEntity);
		}
		return null;
	}
}
