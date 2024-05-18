package com.kiz.springJwt.Repository;

import com.kiz.springJwt.model.Token;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenRepository extends JpaRepository<Token, Integer> {


    @Query("""
            SELECT t FROM Token t INNER JOIN t.user u WHERE u.id = :userId AND t.loggedOut = false
        """)
    List<Token> findAllAccessTokensByUser(@Param("userId") Integer userId);
    Optional<Token> findByAccessToken(String token);

    Optional<Token> findByRefreshToken(String token);
}
