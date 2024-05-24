package org.zerock.api01.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

@SpringBootTest
@Log4j2
public class JWTUtilTests {
    @Autowired
    private JWTUtil jwtUtil;

    @Test
    public void testGenerateToken() {

        Map<String, Object> claimMap = Map.of("mid", "ABCDE");

        String jwtStr = jwtUtil.generateToken(claimMap, 1);

        log.info(jwtStr);
    }

    @Test
    public void testValidate() {
        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MTY1MjgyNTMsIm1pZCI6IkFCQ0RFIiwiaWF0IjoxNzE2NTI4MTkzfQ.jyvtJIx6IgOnPc_G7_kONQODHhsTYWBzjHFFznkwp2M";

        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);
                log.info(claim);
    }

    @Test
    public void testAll() {
        String jwtStr = jwtUtil.generateToken(Map.of("mid", "AAAA", "email", "aaa@bbb"), 1);
        log.info(jwtStr);
        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);
        log.info("mid: " + claim.get("mid"));
        log.info("email: " + claim.get("email"));
    }
}
