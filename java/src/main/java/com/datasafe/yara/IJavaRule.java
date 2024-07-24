package com.datasafe.yara;

import java.util.List;

/**
 * @author gaosg
 */
public interface IJavaRule {
    MatchingRules scan(byte[] data);
}