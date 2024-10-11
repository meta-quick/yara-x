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
                    "                $_a = \"hello\"\n" +
                    "                $_b = \"world\"\n" +
                    "            condition:\n" +
                    "                a\n" +
                    "        }");

            engine.addNamespace("demo2");
            engine.addSource("rule test1 {\n" +
                    "            meta:\n" +
                    "                author = \"gao\"\n" +
                    "            strings:\n" +
                    "                $_a = \"hello\"\n" +
                    "                $_b = \"world\"\n" +
                    "                $_c =/\b(1[0-9]{2}|2[0-4][0-9]|[1-9]?[0-9](\\.[0-9]{1,2})?)\b/"+
                    "            condition:\n" +
                    "                $_c" +
                    "        }");

            engine.build();
            ScanResults result = engine.scan("foobar hello world".getBytes());
            System.out.println(result);
        }catch (Throwable e){
            e.printStackTrace();
        }
    }
}
