package com.datasafe.yara;

import com.google.gson.Gson;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;

/**
 * @author gaosg
 */
public class Engine implements AutoCloseable {
    private static native long nativeNewYaraCompiler(boolean relaxed_re_syntax,boolean error_on_slow_pattern);
    private static native long nativeYaraCompilerNewNamespace(long compiler, String namespace);
    private static native long nativeYaraCompilerAddSource(long compiler, String source);
    private static native long nativeYaraCompilerAddFile(long compiler, String filePath);
    private static native long nativeYaraCompilerAddFileWithNamespace(long compiler, String filePath);
    private static native long nativeYaraCompilerBuild(long compiler);
    private static native long nativeCloseYaraCompiler(long compiler);


    private static native long nativeNewScanner(long rules);
    private static native String nativeScannerScan(long scanner,byte[] data);
    private static native long nativeCloseScanner(long scanner);


    private long compiler;
    private long scanner;
    private long rules;

    private ArrayList<IJavaRule> internalRules = new ArrayList<>();

    public Engine() {
        compiler = nativeNewYaraCompiler(true,true);
        if (compiler == 0) {
            throw new RuntimeException("Failed to create YARA compiler");
        }
    }

    public void addNamespace(String namespace) {
        long result = nativeYaraCompilerNewNamespace(compiler, namespace);
        if (result == -1) {
            throw new RuntimeException("Failed to add namespace to YARA compiler");
        }
    }

    public void addSource(String source) {
        long result = nativeYaraCompilerAddSource(compiler, source);
        if (result == -1) {
            throw new RuntimeException("Failed to add source to YARA compiler");
        }
    }

    public void addFile(String filePath) {
        long result = nativeYaraCompilerAddFile(compiler, filePath);
        if (result == -1) {
            throw new RuntimeException("Failed to add file to YARA compiler");
        }
    }

    public void addFileWithNamespace(String filePath) {
        long result = nativeYaraCompilerAddFileWithNamespace(compiler, filePath);
        if (result == -1) {
            throw new RuntimeException("Failed to add file to YARA compiler");
        }
    }

    public void build() {
        rules = nativeYaraCompilerBuild(compiler);
        if (rules == -1) {
            throw new RuntimeException("Failed to build YARA compiler");
        }
        scanner = nativeNewScanner(rules);
        if (scanner == -1) {
            throw new RuntimeException("Failed to create YARA scanner");
        }
    }

    @Override
    public void close() {
        if (compiler != 0) {
            nativeCloseYaraCompiler(compiler);
            compiler = 0;
        }
        if (scanner != 0 && rules != -1) {
            nativeCloseScanner(scanner);
            scanner = 0;
            rules = 0;
        }
    }

    public void registerJavaRules(ArrayList<IJavaRule> rules) {
        this.internalRules = rules;
    }

    public void registerJavaRule(IJavaRule rule) {
        this.internalRules.add(rule);
    }

    public void clearJavaRules(){
        this.internalRules.clear();
    }

    public ScanResults scanJavaRules(byte[] data){
        ScanResults scanResults = new ScanResults();
        for (IJavaRule rule : internalRules) {
            MatchingRules matchingRules = rule.scan(data);
            if (matchingRules != null) {
                scanResults.addMatchingRule(matchingRules);
            }
        }
        if (!scanResults.matching_rules.isEmpty()) {
            return scanResults;
        }
        return null;
    }

    public ScanResults scan(byte[] data) {
        if (scanner != 0 && rules != -1){
            String result = nativeScannerScan(scanner, data);
            if (result == null) {
                throw new RuntimeException();
            }

            //JSON deserialization from result string into ScanResults
            Gson gson = new Gson();
            return gson.fromJson(result, ScanResults.class);
        }
        return null;
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
}