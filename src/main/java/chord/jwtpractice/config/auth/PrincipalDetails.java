package chord.jwtpractice.config.auth;

//오브젝트 타입 : Authentication 타입 객체
//Authentication 객체 안에 User 정보가 있어야 함
// User오브젝트타입 => UserDetails 타입 객체

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import chord.jwtpractice.model.User;
import lombok.Data;

//Security Session => Authentication => UserDetails(PrincipalDetails)
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

	private User user;
	private Map<String, Object> attributes;

	//일반 로그인
	public PrincipalDetails(User user) {
		this.user = user;
	}
	//oauth 로그인
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	//해당 유저의 권한을 return하는 곳;
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<>();
		collect.add(new GrantedAuthority() {
			@Override
			public String getAuthority() {
				return user.getRole();
			}
		});
		return collect;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	//계정 기한 만료
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	//계정 잠긴 계정인지
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	//기한이 지났는지
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		//우리 사이트에서 1년동안 로그인을 안해서 휴면계정이 되었을 때
		return true;
	}

	@Override
	public String getName() {
		return null;
	}
}
