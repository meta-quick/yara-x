package com.datasafe.yara;

import lombok.Data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * @author gaosg
 */
@Data
public class ScanResults {
    List<MatchingRules> matching_rules;
    HashMap<String, String> module_outputs;

    public ScanResults() {
        matching_rules = new ArrayList<>();
        module_outputs = new LinkedHashMap<>();
    }

    public void merge(ScanResults results) {
        matching_rules.addAll(results.matching_rules);
        module_outputs.putAll(results.module_outputs);
    }

    public void addMatchingRule(MatchingRules rule) {
        matching_rules.add(rule);
    }

    public void addModuleOutput(String key, String value) {
        module_outputs.put(key, value);
    }

    @Override
    public String toString() {
        //Pretty print
        StringBuilder sb = new StringBuilder();
        if (matching_rules != null) {
            sb.append("Matching Rules:\n");
            for (MatchingRules rule : matching_rules) {
                sb.append(rule.toString());
                sb.append("\n");
            }
        }

        if (module_outputs != null) {
            sb.append("Module Outputs:\n");
            for (String key : module_outputs.keySet()) {
                sb.append(key);
                sb.append(": ");
                sb.append(module_outputs.get(key));
                sb.append("\n");
            }
        }

        return sb.toString();
    }
}
