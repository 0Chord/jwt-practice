package chord.jwtpractice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import chord.jwtpractice.model.User;
import chord.jwtpractice.repository.UserRepository;

@Controller
public class IndexController {

	@Autowired
	UserRepository userRepository;
	@Autowired
	BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping({"", "/"})
	public String index() {
		return "index";
	}

	@GetMapping("/user")
	public @ResponseBody String user() {
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

}

