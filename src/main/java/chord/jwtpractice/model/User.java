package chord.jwtpractice.model;

import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import org.hibernate.annotations.CreationTimestamp;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	private String username;
	private String password;
	private String email;
	private String role;

	private String provider;//oauth2 제공 업체
	private String providerId;//
	@CreationTimestamp
	private Timestamp createDate;
	@Builder
	public User(String username, String password, String email, String role, String provider, String providerId) {
		this.username = username;
		this.password = password;
		this.email = email;
		this.role = role;
		this.provider = provider;
		this.providerId = providerId;
	}
}
