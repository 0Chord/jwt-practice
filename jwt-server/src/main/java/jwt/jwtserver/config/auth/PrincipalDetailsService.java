package jwt.jwtserver.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import jwt.jwtserver.model.User;
import jwt.jwtserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;

//http://localhost:8080/login/
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUsername(username);

		return new PrincipalDetails(userEntity);
	}
}
