package io.jenkins.plugins.venaficodesigning;

import java.io.IOException;
import java.util.Map;

import javax.annotation.Nonnull;

/**
 * Allows starting a process, waiting for it to finish, and retrieving
 * its exit code and output. Its API is similar to {@link hudson.Launcher}.
 * We use this interface instead of hudson.Launcher directly so that
 * we can mock its behavior in tests.
 *
 * <p>
 * There are two implementations:
 *
 * <ul>
 * <li>{@link RealCommandLauncher}</li>
 * <li>{@link MockCommandLauncher}</li>
 * </ul>
 */
public interface CommandLauncher {
    public CommandLauncher cmds(@Nonnull String... args);
    public CommandLauncher envs(@Nonnull Map<String, String> overrides);
    public CommandLauncher masks(@Nonnull boolean... values);
    public CommandLauncher quiet(boolean value);
    public CommandLauncher pwd(@Nonnull String path);
    public void startAndJoin() throws IOException, InterruptedException;
    public int getCode();
    public String getOutput();
}
