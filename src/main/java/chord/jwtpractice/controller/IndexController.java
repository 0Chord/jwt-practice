package chord.jwtpractice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import chord.jwtpractice.config.auth.PrincipalDetails;
import chord.jwtpractice.model.User;
import chord.jwtpractice.repository.UserRepository;

@Controller
public class IndexController {

	@Autowired
	UserRepository userRepository;
	@Autowired
	BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping("/test/login")
	public @ResponseBody String loginTest(Authentication authentication,
		@AuthenticationPrincipal PrincipalDetails userDetails) {
		System.out.println("====================");
		PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
		System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
		System.out.println("userDetails = " + userDetails.getUser());
		return "세션 정보 확인하기";
	}

	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOauthLogin(Authentication authentication,
		@AuthenticationPrincipal OAuth2User oauth) {
		System.out.println("====================");
		OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
		System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());
		System.out.println("oauth.getAttributes() = " + oauth.getAttributes());
		return "Oauth2 세션 정보 확인하기";
	}

	@GetMapping({"", "/"})
	public String index() {
		return "index";
	}

	//일반 로그인을 해도 principalDetails 타입으로 받아짐
	// oauth 로그인을 해도 principalDetails 타입으로 받아짐
	@GetMapping("/user")
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
		return "user";
	}

	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}

	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}

	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}

	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}

	@PostMapping("/join")
	public String join(User user) {
		System.out.println("user = " + user);
		user.setRole("ROLE_USER");
		String encPassword = bCryptPasswordEncoder.encode(user.getPassword());
		user.setPassword(encPassword);
		userRepository.save(user);
		return "redirect:/loginForm";
	}

	@Secured("ROLE_ADMIN")
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인정보";
	}

	@PreAuthorize("hasRole('ROLE_MANGER') or hasRole('ROLE_ADMIN')")
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터 정보";
	}

}

