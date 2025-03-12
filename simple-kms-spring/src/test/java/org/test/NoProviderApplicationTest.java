package org.test;


import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(classes = Application.class)
@ActiveProfiles("no-provider")
class NoProviderApplicationTest {

//    @Autowired
//    private EncryptionEngine encryptionEngine;

    @Test
    void test() {


        assertEquals("hello world", "hello world");
    }
}
