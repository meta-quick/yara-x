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
            results.add(new RecallResults(engine.scan(data),MatchType.MATCH_CONTENT,50));
        }

        if (comments != null) {
            strategy.execute(batch);
            results.add(new RecallResults(engine.scan(comments),MatchType.MATCH_COMMENT,90));
        }

        if (meta != null) {
            strategy.execute(batch);
            results.add(new RecallResults(engine.scan(meta),MatchType.MATCH_META,70));
        }

        strategy.finish(batch);
        return results;
    }

    @Override
    public void close() throws Exception {
        engine.close();
    }
}
