package com.datasafe.yara.impl;

import com.datasafe.yara.IJavaRule;
import com.datasafe.yara.MatchingRules;
import com.datasafe.yara.Metadata;
import com.datasafe.yara.Patterns;

import java.util.List;

public class JavaRuleBase implements IJavaRule {
    private String identifier;
    private String namespace;
    private List<Metadata> metadata;
    private List<Patterns> patterns;

    public JavaRuleBase(String identifier, String namespace, List<Metadata> metadata, List<Patterns> patterns) {
        this.identifier = identifier;
        this.namespace = namespace;
        this.metadata = metadata;
        this.patterns = patterns;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public void setMetadata(List<Metadata> metadata) {
        this.metadata = metadata;
    }

    public void setPatterns(List<Patterns> patterns) {
        this.patterns = patterns;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getNamespace() {
        return namespace;
    }

    public List<Metadata> getMetadata() {
        return metadata;
    }

    public List<Patterns> getPatterns() {
        return patterns;
    }

    @Override
    public MatchingRules scan(byte[] data) {
        return null;
    }
}
