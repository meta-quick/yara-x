package com.datasafe.yara.impl;

import com.datasafe.yara.iScanStrategy;

import java.util.concurrent.atomic.AtomicLong;

/**
 * @author gaosg
 */
public class SpeedLimitStrategy implements iScanStrategy {
    private AtomicLong _batch = new AtomicLong(0);
    private long _speedLimit;

    public SpeedLimitStrategy(long speedLimit) {
        _speedLimit = speedLimit;
    }

    @Override
    public long begin() {
        return  _batch.addAndGet(1);
    }

    @Override
    public void execute(long batch) {
        try {
           Thread.sleep(_speedLimit);
        }catch (InterruptedException ignored) {
        }
    }

    @Override
    public void finish(long batch) {

    }
}
