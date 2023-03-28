package chord.jwtpractice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import chord.jwtpractice.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {

}
