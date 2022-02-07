package com.janek.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.janek.jwt.model.User;

public interface UserRepository extends JpaRepository<User, Long>{
	public User findByUsername(String username);
}
