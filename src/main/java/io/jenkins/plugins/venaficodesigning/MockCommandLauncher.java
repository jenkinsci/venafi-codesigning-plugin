package io.jenkins.plugins.venaficodesigning;

import java.io.IOException;
import java.util.Map;

import javax.annotation.Nonnull;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class MockCommandLauncher implements CommandLauncher {
    private String[] cmds;
    private Map<String, String> envs;
    private boolean quiet = false;
    private String pwd;
    private boolean started = false;
    private String output;
    private int code = -1;

    @SuppressFBWarnings("EI_EXPOSE_REP")
    public String[] cmds() {
        return cmds;
    }

    @Override
    public CommandLauncher cmds(@Nonnull String... args) {
        cmds = args;
        return this;
    }

    public Map<String, String> envs() {
        return envs;
    }

    @Override
    public CommandLauncher envs(@Nonnull Map<String, String> overrides) {
        envs = overrides;
        return this;
    }

    @Override
    public CommandLauncher masks(@Nonnull boolean... values) {
        return this;
    }

    public boolean quiet() {
        return quiet;
    }

    @Override
    public CommandLauncher quiet(boolean value) {
        quiet = value;
        return this;
    }

    public String pwd() {
        return pwd;
    }

    @Override
    public CommandLauncher pwd(@Nonnull String path) {
        pwd = path;
        return this;
    }

    @Override
    public void startAndJoin() throws IOException, InterruptedException {
        started = true;
    }

    public boolean isStarted() {
        return started;
    }

    @Override
    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    @Override
    public String getOutput() {
        return output;
    }

    public void setOutput(String value) {
        output = value;
    }
}
