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



    public ArrayList<ScanResults> scan(ArrayList<byte[]> data){
        ArrayList<ScanResults> results = new ArrayList<>();
        long batch = strategy.begin();
        for (byte[] bytes : data) {
            results.add(engine.scan(bytes));
            strategy.execute(batch);
        }
        strategy.finish(batch);

        return results;
    }

    @Override
    public void close() throws Exception {
        engine.close();
    }
}
