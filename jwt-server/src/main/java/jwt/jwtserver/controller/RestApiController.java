package jwt.jwtserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jwt.jwtserver.config.auth.PrincipalDetails;
import jwt.jwtserver.model.User;
import jwt.jwtserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class RestApiController {
	private final BCryptPasswordEncoder encoder;
	private final UserRepository userRepository;

	@GetMapping("home")
	public String home() {
		return "<h1>Home</h1>";
	}

	@PostMapping("token")
	public String token() {
		return "<h1>token</h1>";
	}

	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(encoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입 완료";
	}

	@GetMapping("/api/v1/user")
	public String user(Authentication authentication){
		PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("principal : " + principal.getUser().getId());
		System.out.println("principal : " + principal.getUser().getUsername());
		System.out.println("principal : " + principal.getUser().getPassword());
		return "user";
	}

	@GetMapping("/api/v1/manager")
	public String manager(){
		return "manager";
	}

	@GetMapping("/api/v1/admin")
	public String admin(){
		return "admin";
	}
}

