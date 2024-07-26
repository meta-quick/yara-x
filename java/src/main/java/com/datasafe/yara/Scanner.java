package com.datasafe.yara;

import lombok.Setter;
import java.util.ArrayList;

/**
 * @author gaosg
 */
@Setter
public class Scanner implements AutoCloseable {
    private Engine engine;

    @Setter
    private iScanStrategy strategy;


    public Scanner()
    {
        engine = new Engine();
    }

    public void addFile(String filePath)
    {
        engine.addFile(filePath);
    }

    public void registerJavaRule(IJavaRule rule)
    {
        engine.registerJavaRule(rule);
    }

    public void registerJavaRules(ArrayList<IJavaRule> rules)
    {
        engine.registerJavaRules(rules);
    }

    public void clearJavaRules(IJavaRule rule)
    {
        engine.registerJavaRule(rule);
    }

    public void clearJavaRules()
    {
        engine.clearJavaRules();
    }

    public void addFileWithNamespace(String filePath)
    {
        engine.addFileWithNamespace(filePath);
    }

    public void addNamespace(String namespace)
    {
        engine.addNamespace(namespace);
    }

    public void addSource(String source)
    {
        engine.addSource(source);
    }

    public void build()
    {
        engine.build();
    }

    public ArrayList<RecallResults> scan(byte[] comments,byte[] meta,byte[] data){
        ArrayList<RecallResults> results = new ArrayList<>();
        long batch = strategy.begin();
        if (data != null) {
            strategy.execute(batch);
            ScanResults ret = engine.scan(data);
            if (ret != null) {
                results.add(new RecallResults(ret,MatchType.MATCH_CONTENT,50));
            }
            ret = engine.scanJavaRules(data);
            if (ret != null) {
                results.add(new RecallResults(ret,MatchType.MATCH_CONTENT,50));
            }
        }

        if (comments != null) {
            strategy.execute(batch);
            ScanResults ret = engine.scan(comments);
            if (ret != null) {
                results.add(new RecallResults(ret,MatchType.MATCH_COMMENT,80));
            }
            ret = engine.scanJavaRules(comments);
            if (ret != null) {
                results.add(new RecallResults(ret,MatchType.MATCH_COMMENT,80));
            }
        }

        if (meta != null) {
            strategy.execute(batch);
            ScanResults ret = engine.scan(meta);
            if (ret != null) {
                results.add(new RecallResults(ret,MatchType.MATCH_META,70));
            }
            ret = engine.scanJavaRules(meta);
            if (ret != null) {
                results.add(new RecallResults(ret,MatchType.MATCH_META,70));
            }
        }

        strategy.finish(batch);
        return results;
    }

    @Override
    public void close() throws Exception {
        engine.close();
    }
}
