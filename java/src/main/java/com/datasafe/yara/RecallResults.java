package com.datasafe.yara;

import lombok.Data;

/**
 * @author gaosg
 */
@Data
public class RecallResults {
    public MatchType type;
    public long weight;
    public ScanResults results;

    public RecallResults(ScanResults results,MatchType type, long weight) {
        this.type = type;
        this.weight = weight;
        this.results = results;
    }
}
