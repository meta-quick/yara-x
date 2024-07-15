package com.datasafe.yara.impl;

import com.datasafe.yara.iScanStrategy;

import java.util.concurrent.atomic.AtomicLong;

/**
 * @author gaosg
 */
public class NullStrategy implements iScanStrategy {
    private AtomicLong _batch = new AtomicLong(0);
    public NullStrategy() {
    }
    @Override
    public long begin() {
        return  _batch.addAndGet(1);
    }

    @Override
    public void execute(long batch) {
    }

    @Override
    public void finish(long batch) {
    }
}
