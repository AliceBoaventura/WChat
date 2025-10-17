package com.wchat;

import java.text.DateFormat;
import java.util.Date;

public final class PrototypeMessageFormatter {

    private PrototypeMessageFormatter() {
        // Utility class
    }

    public static String buildMessage(String recipient, String message, boolean includeTimestamp) {
        StringBuilder builder = new StringBuilder();
        builder.append("\uD83D\uDC4B ")
                .append(recipient)
                .append(",\n");
        builder.append(message);
        builder.append("\n\n— WeChat Companion");

        if (includeTimestamp) {
            DateFormat format = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT);
            builder.append("\n\u23F1 ")
                    .append(format.format(new Date()));
        }

        return builder.toString();
    }
}