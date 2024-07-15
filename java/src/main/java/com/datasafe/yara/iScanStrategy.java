package com.datasafe.yara;

/**
 * @author gaosg
 */
public interface iScanStrategy {
    public long begin();
    public void execute(long batch);
    public void finish(long batch);
}
