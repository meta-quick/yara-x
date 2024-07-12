package com.datasafe.yara;

import lombok.Data;

import java.util.List;

@Data
public class Patterns {
    private String identifier;
    private List<Matches> matches;
}
