package com.datasafe.yara;


import lombok.Data;

import java.util.List;

/**
 * @author gaosg
 */
@Data
public class MatchingRules {
    private String identifier;
    private String namespace;
    private List<Metadata> metadata;
    private List<Patterns> patterns;
}
