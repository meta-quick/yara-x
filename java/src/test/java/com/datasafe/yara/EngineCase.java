package com.datasafe.yara;

import junit.framework.TestCase;

public class EngineCase extends TestCase {

    public void testEngine() throws Exception {
        try (Engine engine = new Engine()) {
            assertNotNull(engine);
        }
    }
}
