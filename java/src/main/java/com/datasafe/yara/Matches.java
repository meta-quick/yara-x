package com.datasafe.yara;

import lombok.Data;

/**
 * @author gaosg
 */
@Data
public class Matches {
    private int offset;
    private int length;
    private boolean xorKey;
}
