package com.datasafe.yara;

import junit.framework.TestCase;

public class EngineCase extends TestCase {

    public void testEngine() throws Exception {
        try (Engine engine = new Engine()) {
            assertNotNull(engine);

            engine.addNamespace("demo");

            engine.addSource("rule test {\n" +
                    "            meta:\n" +
                    "                author = \"gao\"\n" +
                    "                level = 2 \n" +
                    "                category = \"PII\" \n" +
                    "            strings:\n" +
                    "                $a = \"foo\"\n" +
                    "                $b = \"bar\"\n" +
                    "            condition:\n" +
                    "                all of them\n" +
                    "        }");

            engine.addNamespace("demo1");
            engine.addSource("rule test1 {\n" +
                    "            meta:\n" +
                    "                author = \"gao\"\n" +
                    "            strings:\n" +
                    "                $a = \"hello\"\n" +
                    "                $b = \"world\"\n" +
                    "            condition:\n" +
                    "                all of them\n" +
                    "        }");

            engine.build();
            ScanResults result = engine.scan("foobar hello world".getBytes());
            System.out.println(result);
        }
    }
}
