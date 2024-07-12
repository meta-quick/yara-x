package com.datasafe.yara;

import lombok.Data;

import java.util.HashMap;
import java.util.List;

/**
 * @author gaosg
 */
@Data
public class ScanResults {
    List<MatchingRules> matching_rules;
    HashMap<String, String> module_outputs;

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
