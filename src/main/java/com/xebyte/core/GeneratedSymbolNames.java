package com.xebyte.core;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class GeneratedSymbolNames {
    private static final Pattern ADDRESS_NAME = Pattern.compile(
            "^(?:FUN|LAB|DAT|PTR|SUB|LOC|UNK|BYTE|WORD|DWORD|QWORD|FLOAT|DOUBLE|UINT|UNDEFINED|s)"
                    + "_[0-9a-f]+(?:\\.[0-9a-f]+)*$"
                    + "|^PTR_(?:DAT|FUN|LAB)_[0-9a-f]+$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern STRING_LABEL =
            Pattern.compile("^[su]_.*_[0-9a-fA-F]{6,}$");
    private static final Pattern COMMENT_NAME = Pattern.compile(
            "(?<![A-Za-z0-9_])"
                    + "(?:FUN|LAB|DAT|SUB|UNK|EXT|OFF|PTR|LOC|BYTE|WORD|DWORD|QWORD"
                    + "|FLOAT|DOUBLE|UINT|UNDEFINED|s)"
                    + "(?:_[A-Za-z0-9]*)*_[0-9a-f]{4,}"
                    + "(?![A-Za-z0-9_]|\\.[0-9a-f])",
            Pattern.CASE_INSENSITIVE);

    private GeneratedSymbolNames() {}

    public record CommentNameMention(String name, int start, int end) {}

    public static boolean isGenerated(String name) {
        if (name == null || name.isBlank()) return true;
        return ADDRESS_NAME.matcher(name).matches()
                || STRING_LABEL.matcher(name).matches()
                || name.startsWith("Ordinal_")
                || name.startsWith("thunk_FUN_")
                || name.startsWith("thunk_Ordinal_");
    }

    public static List<CommentNameMention> findCommentNameMentions(String text) {
        List<CommentNameMention> mentions = new ArrayList<>();
        if (text == null || text.isEmpty()) return mentions;
        Matcher matcher = COMMENT_NAME.matcher(text);
        while (matcher.find()) {
            mentions.add(new CommentNameMention(
                    matcher.group(), matcher.start(), matcher.end()));
        }
        return mentions;
    }

    public static boolean isCommentAddressName(String name) {
        return name != null && COMMENT_NAME.matcher(name).matches();
    }
}
