package chord.jwtpractice.config.oauth;

import static com.fasterxml.jackson.databind.type.LogicalType.*;

import java.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import chord.jwtpractice.config.auth.PrincipalDetails;
import chord.jwtpractice.config.oauth.provider.FacebookUserInfo;
import chord.jwtpractice.config.oauth.provider.GoogleUserInfo;
import chord.jwtpractice.config.oauth.provider.NaverUserInfo;
import chord.jwtpractice.config.oauth.provider.OAuth2UserInfo;
import chord.jwtpractice.model.User;
import chord.jwtpractice.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	@Autowired
	UserRepository userRepository;

	//구글로 부터 받은 userRequest 정보에 대한 후처리 함수
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("userRequest = " + userRequest.getClientRegistration());
		System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken().getTokenValue());
		//구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인 완료 -> code를 리턴(Oauth-Client라이브러리) -> AccessToken 요청
		// userRequest 정보 -> 회원프로필 정보 받아야 함(loadUser 메서드) -> 구글로 부터 회원프로필
		OAuth2User oAuth2User = super.loadUser(userRequest);
		System.out.println("super.loadUser(userRequest).getAttributes() = " + oAuth2User.getAttributes());

		OAuth2UserInfo oAuth2UserInfo = null;
		if (Objects.equals(userRequest.getClientRegistration().getRegistrationId(), "google")) {
			System.out.println("google 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
		} else if (Objects.equals(userRequest.getClientRegistration().getRegistrationId(), "facebook")) {
			System.out.println("facebook 로그인 요청");
			oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
		} else if (Objects.equals(userRequest.getClientRegistration().getRegistrationId(), "naver")) {
			oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
		} else {
			System.out.println("페이스북과 구글만 지원");
		}
		assert oAuth2UserInfo != null;
		String provider = oAuth2UserInfo.getProvider();
		String providerId = oAuth2UserInfo.getProviderId();
		String username = provider + "_" + providerId;
		String email = oAuth2UserInfo.getEmail();
		String password = bCryptPasswordEncoder.encode("겟인데어");
		String role = "ROLE_USER";

		User userEntity = userRepository.findByUsername(username);
		if (userEntity == null) {
			userEntity = User.builder().username(username).password(password).email(email).role(role).provider(provider)
				.providerId(providerId).build();
			userRepository.save(userEntity);
		}

		return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
	}
}
