package com.example.jwt;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.service.AuthTokenService;
import com.example.jwt.domain.member.member.service.MemberService;
import com.example.jwt.standard.Util.Ut;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class AuthTokenServiceTest {

    @Autowired
    private AuthTokenService authTokenService;

    @Autowired
    private MemberService memeberService;

    @Test
    @DisplayName("AuthTokenService 생성")
    void init() {
        assertThat(authTokenService).isNotNull();
    }

    @Test
    @DisplayName("jwt 생성")
    void createToken() {

        // 토큰 만료기간 : 1년
        int expireSeconds = 60 * 60 * 24 * 365;

        // 토큰 시크릿 키
        Key secretKey = Keys.hmacShaKeyFor("abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890".getBytes());

        String jwt = Ut.Jwt.createToken(secretKey, expireSeconds, Map.of("name", "john", "age", 23));

        assertThat(jwt).isNotBlank();
        System.out.println("jwt = " + jwt);
    }

    @Test
    @DisplayName("access token 생성")
    void accessToken() {

        Member member = memeberService.findByUsername("user1").get();
        String accessToken = authTokenService.genAccessToken(member);

        assertThat(accessToken).isNotBlank();

        System.out.println("accessToken = " + accessToken);
    }
}
