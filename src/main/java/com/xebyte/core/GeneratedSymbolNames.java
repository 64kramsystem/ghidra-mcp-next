package com.xebyte.core;

import java.util.regex.Pattern;

public final class GeneratedSymbolNames {
    private static final Pattern ADDRESS_NAME = Pattern.compile(
            "^(?:FUN|LAB|DAT|PTR|SUB|LOC|UNK|BYTE|WORD|DWORD|QWORD|FLOAT|DOUBLE|UINT|UNDEFINED|s)"
                    + "_[0-9a-f]+(?:\\.[0-9a-f]+)*$"
                    + "|^PTR_(?:DAT|FUN|LAB)_[0-9a-f]+$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern STRING_LABEL =
            Pattern.compile("^[su]_.*_[0-9a-fA-F]{6,}$");

    private GeneratedSymbolNames() {}

    public static boolean isGenerated(String name) {
        if (name == null || name.isBlank()) return true;
        return ADDRESS_NAME.matcher(name).matches()
                || STRING_LABEL.matcher(name).matches()
                || name.startsWith("Ordinal_")
                || name.startsWith("thunk_FUN_")
                || name.startsWith("thunk_Ordinal_");
    }
}
