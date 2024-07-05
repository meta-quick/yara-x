package com.datasafe.yara;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * @author gaosg
 */
public class Engine implements AutoCloseable {
    private static native long nativeNewYaraCompiler();


    private long compiler;

    public Engine() {
        compiler = nativeNewYaraCompiler();
        if (compiler == 0) {
            throw new RuntimeException("Failed to create YARA compiler");
        }
    }



    static {
        final StringBuilder targetTripleBuilder = new StringBuilder();

        final String arch = System.getProperty("os.arch").toLowerCase();
        if (arch.equals("aarch64")) {
            targetTripleBuilder.append("aarch64");
        } else {
            targetTripleBuilder.append("x86_64");
        }
        targetTripleBuilder.append("-");

        final String os = System.getProperty("os.name").toLowerCase();
        if (os.startsWith("windows")) {
            targetTripleBuilder.append("pc-windows-msvc");
        } else if (os.startsWith("mac")) {
            targetTripleBuilder.append("apple-darwin");
        } else {
            targetTripleBuilder.append("unknown-linux-gnu");
        }

        loadNativeLibrary(targetTripleBuilder.toString());
    }

    private static void loadNativeLibrary(String targetTriple) {
        try {
            // try dynamic library - the search path can be configured via "-Djava.library.path"
            System.loadLibrary("yara_java");
            return;
        } catch (UnsatisfiedLinkError ignore) {
            // ignore - try from classpath
        }

        // `aarch64-apple-darwin/libyara_java.dylib`
        final String libraryName = System.mapLibraryName("yara_java");
        final String libraryPath = "/" + targetTriple + "/" + libraryName;

        try (final InputStream is = Engine.class.getResourceAsStream(libraryPath)) {
            if (is == null) {
                throw new RuntimeException("Cannot find " + libraryPath);
            }
            final int dot = libraryPath.indexOf('.');
            final File tmpFile = File.createTempFile(libraryPath.substring(0, dot), libraryPath.substring(dot));
            tmpFile.deleteOnExit();
            Files.copy(is, tmpFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            System.load(tmpFile.getAbsolutePath());
        } catch (IOException exception) {
            throw new RuntimeException(exception);
        }
    }

    @Override
    public void close() throws Exception {

    }
}