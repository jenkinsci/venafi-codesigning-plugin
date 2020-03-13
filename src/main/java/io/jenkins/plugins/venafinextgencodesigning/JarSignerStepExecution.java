package io.jenkins.plugins.venafinextgencodesigning;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.NotImplementedException;
import org.jenkinsci.plugins.workflow.graph.FlowNode;
import org.jenkinsci.plugins.workflow.steps.AbstractStepExecutionImpl;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.support.actions.PauseAction;
import org.jenkinsci.remoting.RoleChecker;

import hudson.FilePath;
import hudson.Launcher;
import hudson.Platform;
import hudson.Proc;
import hudson.FilePath.FileCallable;
import hudson.model.Computer;
import hudson.model.Node;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import jenkins.security.MasterToSlaveCallable;

public class JarSignerStepExecution extends AbstractStepExecutionImpl {
    private static final long serialVersionUID = 1;
    private static transient Map<String, String> locks = new HashMap<>();
    private JarSignerStep step;
    private transient Thread thread;

    public JarSignerStepExecution(JarSignerStep step, StepContext context) {
        super(context);
        this.step = step;
    }

    @Override
    public boolean start() throws Exception {
        PrintStream logger = getContext().get(TaskListener.class).getLogger();
        FilePath ws = getContext().get(FilePath.class);
        Run<?, ?> run = getContext().get(Run.class);
        FlowNode flowNode = getContext().get(FlowNode.class);
        Launcher launcher = getContext().get(Launcher.class);
        Computer wsComputer = ws.toComputer();
        if (wsComputer == null) {
            throw new IOException("Unable to retrieve computer for workspace");
        }
        Node wsNode = wsComputer.getNode();
        if (wsNode == null) {
            throw new IOException("Unable to retrieve node for workspace");
        }
        FilePath nodeRoot = wsNode.getRootPath();
        if (nodeRoot == null) {
            throw new IOException("Unable to retrieve root path of node");
        }

        log(logger, "Using TPM server configuration: %s", step.getTpmServerName());
        TpmServerConfig tpmServerConfig = PluginConfig.get().getTpmServerConfigByName(
            step.getTpmServerName());
        if (tpmServerConfig == null) {
            throw new RuntimeException("No TPM server configuration with name '"
                + step.getTpmServerName() + "' found");
        }

        AgentInfo agentInfo = nodeRoot.act(new GetAgentInfo());
        logger.println("[" + step + "] Detected OS: " + agentInfo.osType);

        String lockKey = calculateLockKey(wsComputer, agentInfo);
        return lock(logger, flowNode, run, lockKey, () -> {
            try {
                loginTpmServer(logger, launcher, ws, agentInfo, tpmServerConfig);
                //invokeJarSigner(logger);
                getContext().onSuccess(null);
            } catch (Exception e) {
                getContext().onFailure(e);
            } finally {
                logoutTpmServer(logger, ws, agentInfo);
            }
        });
    }

    @Override
    public void stop(Throwable cause) throws Exception {
        PrintStream logger = getContext().get(TaskListener.class).getLogger();
        log(logger, "Stopping...");

        if (thread == null) {
            getContext().onFailure(cause);
        } else {
            // We let the thread take care of calling onSuccess()/onFailure().
            thread.interrupt();
            try {
                thread.join();
            } catch (InterruptedException e) {
                // Ignore this and let the caller call us again
                // if it's not satisfied.
            }
            // Not using 'finally': only set null once we know the thread
            // is gone, because it's legal for stop() to be called again.
            thread = null;
        }
    }

    @Override
    public void onResume() {
        TaskListener taskListener;
        try {
            taskListener = getContext().get(TaskListener.class);
        } catch (Exception e) {
            getContext().onFailure(e);
            return;
        }

        PrintStream logger = taskListener.getLogger();
        log(logger, "Resuming...");
        log(logger, "ERROR: resuming not supported by this plugin.");
        getContext().onFailure(new RuntimeException("Resuming not supported by "
            + Messages.JarSignerStep_functionName()));
    }

    private void loginTpmServer(PrintStream logger, Launcher launcher, FilePath ws,
        AgentInfo agentInfo, TpmServerConfig tpmServerConfig)
        throws InterruptedException, IOException, RuntimeException
    {
        invokePkcs11ConfigSetUrl(logger, launcher, ws, tpmServerConfig);
        invokePkcs11ConfigTrust(logger, launcher, ws, tpmServerConfig);
        //invokePkcs11ConfigGetGrant(logger, launcher, ws, tpmServerConfig);
    }

    private void invokePkcs11ConfigSetUrl(PrintStream logger, Launcher launcher, FilePath ws,
        TpmServerConfig tpmServerConfig)
        throws InterruptedException, IOException
    {
        invokeCommand(logger, launcher, ws,
            "Logging into TPM server: configuring client: setting URL.",
            "Successfully set URL configuration.",
            "Error setting URL configuration",
            "pkcs11config seturl",
            new String[]{
                "pkcs11config",
                "seturl",
                "--authurl=" + tpmServerConfig.getAuthUrl(),
                "--hsmurl=" + tpmServerConfig.getHsmUrl()
            });
    }

    private void invokePkcs11ConfigTrust(PrintStream logger, Launcher launcher, FilePath ws,
        TpmServerConfig tpmServerConfig)
        throws InterruptedException, IOException
    {
        invokeCommand(logger, launcher, ws,
            "Logging into TPM server: configuring client: establishing trust with server.",
            "Successfully established trust with TPM server.",
            "Error establishing trust with TPM server",
            "pkcs11config trust",
            new String[]{
                "pkcs11config",
                "trust",
                "--hsmurl=" + tpmServerConfig.getHsmUrl()
            });

    }

    private void logoutTpmServer(PrintStream logger, FilePath ws, AgentInfo agentInfo) {
        if (!agentInfo.osType.isUnixCompatible()) {
            // TODO: remove credentials from Windows registry
            log(logger, "WARNING: TPM server logout not yet implemented for Windows nodes");
            return;
        }

        FilePath home;
        try {
            home = FilePath.getHomeDirectory(ws.getChannel());
        } catch (Exception e) {
            e.printStackTrace(logger);
            return;
        }

        FilePath libhsmtrust = home.child(".libhsmtrust");
        FilePath libhsmconfig = home.child(".libhsmconfig");

        log(logger, "Logging out of TPM server: deleting %s", libhsmtrust);
        try {
            deleteFilePathInterruptionSafe(libhsmtrust);
        } catch (InterruptedException e) {
            log(logger, "Error logging out of TPM server: operation interrupted");
            e.printStackTrace(logger);
            return;
        } catch (Exception e) {
            log(logger, "Error logging out of TPM server: %s", e.getMessage());
            e.printStackTrace(logger);
        }

        log(logger, "Logging out of TPM server: deleting %s", libhsmconfig);
        try {
            libhsmconfig.delete();
        } catch (Exception e) {
            log(logger, "Error logging out of TPM server: %s", e.getMessage());
            e.printStackTrace(logger);
        }
    }

    // Deletes the given FilePath. If the thread is interrupted, then it will
    // keep trying to delete the FilePath, and then re-throw the InterruptionException
    // afterwards. This method is useful if we really want to make sure that
    // the file is gone, even if we get interrupted ourselves.
    private void deleteFilePathInterruptionSafe(FilePath path)
        throws IOException, InterruptedException
    {
        InterruptedException interruption = null;

        while (true) {
            try {
                path.delete();
                break;
            } catch (InterruptedException e) {
                interruption = e;
            }
        }

        if (interruption != null) {
            throw interruption;
        }
    }

    private String invokeCommand(PrintStream logger, Launcher launcher, FilePath ws,
        String preMessage, String successMessage, String errorMessage,
        String shortCommandLine, String[] cmdArgs)
        throws InterruptedException, IOException
    {
        log(logger, "%s", preMessage);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Launcher.ProcStarter starter =
            launcher.
            launch().
            cmds(cmdArgs).
            stdout(output).
            pwd(ws);

        Proc proc;
        int code;
        try {
            proc = starter.start();
            code = proc.join();
        } catch (IOException e) {
            log(logger, "%s: %s", errorMessage, e.getMessage());
            throw e;
        }

        if (code == 0) {
            log(logger, "%s", successMessage);
            return output.toString();
        } else {
            log(logger,
                "%s: command exited with code %d. Output from command '%s' is as follows:\n%s",
                errorMessage, code, shortCommandLine, output.toString());
            throw new IOException(errorMessage + ": command exited with code " + code);
        }
    }

    private void log(PrintStream logger, String format, Object... args) {
        logger.println("[" + step + "] " + String.format(format, args));
    }

    private boolean lock(PrintStream logger, FlowNode flowNode, Run<?, ?> run, String key, Runnable continuation) {
        thread = new Thread(() -> {
            try {
                synchronized(locks) {
                    String prevLockHolder;
                    do {
                        logger.println("[" + step + "] Trying to acquire lock with key '" + key + "'");
                        prevLockHolder = locks.putIfAbsent(key, run.toString());
                        if (prevLockHolder != null) {
                            logger.println("[" + step + "] Lock is already held by [" + prevLockHolder + "], waiting...");
                            locks.wait();
                            logger.println("[" + step + "] Lock has been released. Trying again.");
                        }
                    } while (prevLockHolder != null);
                }
            } catch (InterruptedException e) {
                logger.println("[" + step + "] Thread interrupted.");
                return;
            }

            try {
                logger.println("[" + step + "] Lock successfully acquired.");
                PauseAction.endCurrentPause(flowNode);
                continuation.run();
            } catch (IOException e) {
                getContext().onFailure(e);
            } finally {
                logger.println("[" + step + "] Releasing lock with key '" + key + "'");
                synchronized(locks) {
                    locks.remove(key);
                    locks.notifyAll();
                }
            }
        });
        thread.setName(Messages.JarSignerStep_functionName() + " execution");
        thread.start();
        flowNode.addAction(new PauseAction(Messages.JarSignerStep_functionName()));
        return false;
    }

    private String calculateLockKey(Computer computer, AgentInfo agentInfo)
        throws IOException, InterruptedException
    {
        return getFqdn(computer, agentInfo) + ":" + agentInfo.username;
    }

    // Determines the FQDN of the given Computer.
    //
    // Computer.getHostName() (which does return an FQDN) isn't good enough and
    // sometimes fails to detect the hostname. So we fallback to invoking the
    // `hostname -f` command, but only on a Unix-compatible system.
    //
    // Never returns null. If the hostname cannot be determined, then returns
    // the empty string.
    private String getFqdn(Computer computer, AgentInfo agentInfo)
        throws IOException, InterruptedException
    {
        String result = computer.getHostName();
        if (result != null) {
            return result;
        }

        if (!agentInfo.osType.isUnixCompatible()) {
            return "";
        }

        VirtualChannel channel = computer.getChannel();
        if (channel == null) {
            return "";
        }

        return channel.call(new RunHostNameFCommand());
    }

    public static final class RunHostNameFCommand extends MasterToSlaveCallable<String, IOException> {
        private static final long serialVersionUID = 1;
        private static final long TIMEOUT_QTY = 5;
        private static final TimeUnit TIMEOUT_UNIT = TimeUnit.SECONDS;

        public String call() throws IOException {
            ProcessBuilder builder = new ProcessBuilder("hostname", "-f");
            builder.redirectInput(ProcessBuilder.Redirect.INHERIT);
            builder.redirectError(ProcessBuilder.Redirect.INHERIT);
            Process process = builder.start();
            try {
                Reader reader = new InputStreamReader(process.getInputStream());
                return new BufferedReader(reader).readLine().trim();
            } finally {
                boolean done;
                try {
                    done = process.waitFor(TIMEOUT_QTY, TIMEOUT_UNIT);
                } catch (InterruptedException e) {
                    done = false;
                }
                if (!done) {
                    process.destroyForcibly();
                    try {
                        process.waitFor();
                    } catch (InterruptedException e) {
                        // All we can do is ignoring this
                    }
                }
            }
        }
    }

    public static enum OsType {
        MACOS("macOS"),
        GENERIC_UNIX("Unix (generic)"),
        WINDOWS("Windows");

        private String displayName;

        private OsType(String displayName) {
            this.displayName = displayName;
        }

        public boolean isUnixCompatible() {
            return this == MACOS || this == GENERIC_UNIX;
        }

        @Override
        public String toString() {
            return displayName;
        }
    }

    public static final class AgentInfo implements Serializable {
        private static final long serialVersionUID = 1;

        public String username;
        public OsType osType;
    }

    public static final class GetAgentInfo implements FileCallable<AgentInfo> {
        private static final long serialVersionUID = 1;

        @Override
        public AgentInfo invoke(File nodeRoot, VirtualChannel virtualChannel) throws IOException, InterruptedException {
            AgentInfo info = new AgentInfo();
            info.username = System.getProperty("user.name");
            if (Platform.isDarwin()) {
                info.osType = OsType.MACOS;
            } else if (Platform.current() == Platform.WINDOWS) {
                info.osType = OsType.WINDOWS;
            } else {
                info.osType = OsType.GENERIC_UNIX;
            }
            return info;
        }

        @Override
        public void checkRoles(RoleChecker roleChecker) throws SecurityException {
            // Do nothing
        }
    }
}
