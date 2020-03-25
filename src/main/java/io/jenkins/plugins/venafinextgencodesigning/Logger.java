package io.jenkins.plugins.venafinextgencodesigning;

import java.io.PrintStream;

public class Logger {
    private PrintStream output;
    private String prefix;

    public Logger(PrintStream output, String prefix) {
        this.output = output;
        this.prefix = prefix;
    }

    public PrintStream getOutput() {
        return output;
    }

    public void log(String format, Object... args) {
        output.println("[" + prefix + "] " + String.format(format, args));
    }
}
