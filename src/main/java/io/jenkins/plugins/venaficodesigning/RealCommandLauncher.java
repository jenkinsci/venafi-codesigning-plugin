package io.jenkins.plugins.venaficodesigning;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;

import javax.annotation.Nonnull;

import hudson.Launcher;

public class RealCommandLauncher implements CommandLauncher {
    @Nonnull private Launcher jenkinsLauncher;
    @Nonnull private Launcher.ProcStarter starter;
    private ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private int code = -1;

    public RealCommandLauncher(@Nonnull Launcher jenkinsLauncher) {
        this.jenkinsLauncher = jenkinsLauncher;
        this.starter = jenkinsLauncher.launch().stdout(outputStream);
    }

    @Override
    public CommandLauncher cmds(@Nonnull String... args) {
        starter.cmds(args);
        return this;
    }

    @Override
    public CommandLauncher envs(@Nonnull Map<String, String> overrides) {
        starter.envs(overrides);
        return this;
    }

    @Override
    public CommandLauncher masks(@Nonnull boolean... values) {
        starter.masks(values);
        return this;
    }

    @Override
    public CommandLauncher quiet(boolean value) {
        starter.quiet(value);
        return this;
    }

    @Override
    public CommandLauncher pwd(@Nonnull String path) {
        starter.pwd(path);
        return this;
    }

    @Override
    public void startAndJoin() throws IOException, InterruptedException {
        code = starter.start().join();
    }

    @Override
    public int getCode() {
        return code;
    }

    @Override
    public String getOutput() {
        try {
            return outputStream.toString("UTF-8");
        } catch (UnsupportedEncodingException e) {
            // Can never happen
            e.printStackTrace();
            return null;
        }
    }
}
