package io.jenkins.plugins.venafinextgencodesigning;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

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
import hudson.util.Secret;

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

        log(logger, "Using Venafi TPP configuration: %s", step.getTppName());
        TppConfig tppConfig = PluginConfig.get().getTppConfigByName(
            step.getTppName());
        if (tppConfig == null) {
            throw new RuntimeException("No Venafi TPP configuration with name '"
                + step.getTppName() + "' found");
        }

        StandardUsernamePasswordCredentials credentials = Utils.findCredentials(
            tppConfig.getCredentialsId());
        if (credentials == null) {
            throw new RuntimeException("No credentials with ID '"
                + tppConfig.getCredentialsId() + "' found");
        }

        Thread thread = new Thread(() -> {
            executeInBackgroundThread(logger, ws, run, flowNode, launcher, wsComputer,
                wsNode, nodeRoot, tppConfig, credentials);
        });
        thread.setName(Messages.JarSignerStep_functionName() + " execution");
        synchronized(this) {
            this.thread = thread;
            thread.start();
        }

        return false;
    }

    @Override
    public void stop(Throwable cause) throws Exception {
        PrintStream logger = getContext().get(TaskListener.class).getLogger();
        log(logger, "Stopping...");

        Thread thread;
        synchronized(this) {
            thread = this.thread;
        }

        if (thread == null) {
            getContext().onFailure(cause);
        } else {
            // We let the thread take care of calling onSuccess()/onFailure()
            // and to set this.thread to null.
            thread.interrupt();
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

    private void executeInBackgroundThread(PrintStream logger, FilePath ws, Run<?, ?> run,
        FlowNode flowNode, Launcher launcher, Computer wsComputer, Node wsNode,
        FilePath nodeRoot, TppConfig tppConfig,
        StandardUsernamePasswordCredentials credentials)
    {
        try {
            AgentInfo agentInfo = nodeRoot.act(new GetAgentInfo());
            log(logger, "Detected OS: %s", agentInfo.osType);

            FilePath certChainFile = null;

            String lockKey = calculateLockKey(wsComputer, launcher, agentInfo);
            lock(logger, flowNode, run, lockKey);
            try {
                // Jenkins does not necessarily guarantee that our workspace exists.
                ws.mkdirs();

                certChainFile = ws.createTempFile("venafi-certchain", "crt");

                loginTpp(logger, launcher, ws, run, agentInfo, tppConfig,
                    credentials, certChainFile);
                //invokeJarSigner(logger);
                getContext().onSuccess(null);
            } finally {
                logoutTpp(logger, ws, agentInfo);
                unlock(logger, lockKey);
                deleteFileOrPrintStackTrace(logger, certChainFile);
            }
        } catch (Exception e) {
            log(logger, "ERROR: %s", e.getMessage());
            getContext().onFailure(e);
        } finally {
            synchronized(this) {
                thread = null;
            }
        }
    }

    private void loginTpp(PrintStream logger, Launcher launcher, FilePath ws,
        Run<?, ?> run, AgentInfo agentInfo, TppConfig tppConfig,
        StandardUsernamePasswordCredentials credentials, FilePath certChainFile)
        throws InterruptedException, IOException, RuntimeException
    {
        invokePkcs11ConfigGetGrant(logger, launcher, ws, run, tppConfig, credentials);
        invokePkcs11ConfigTrust(logger, launcher, ws, tppConfig);
        invokePkcs11ConfigGetCertificate(logger, launcher, ws, certChainFile);
    }

    private void invokePkcs11ConfigGetGrant(PrintStream logger, Launcher launcher, FilePath ws,
        Run<?, ?> run, TppConfig tppConfig,
        StandardUsernamePasswordCredentials credentials)
        throws InterruptedException, IOException
    {
        CredentialsProvider.track(run, credentials);
        String password = Secret.toString(credentials.getPassword());
        invokeCommand(logger, launcher, ws,
            "Logging into TPP: configuring client: requesting grant from server.",
            "Successfully gotten grant TPP.",
            "Error requesting grant from TPP",
            "pkcs11config getgrant",
            new String[]{
                "pkcs11config",
                "getgrant",
                "--force",
                "--authurl=" + tppConfig.getAuthUrl(),
                "--hsmurl=" + tppConfig.getHsmUrl(),
                "--username=" + credentials.getUsername(),
                "--password=" + password
            },
            new boolean[] {
                false,
                false,
                false,
                false,
                false,
                false,
                true
            });
    }

    private void invokePkcs11ConfigTrust(PrintStream logger, Launcher launcher, FilePath ws,
        TppConfig tppConfig)
        throws InterruptedException, IOException
    {
        invokeCommand(logger, launcher, ws,
            "Logging into TPP: configuring client: establishing trust with server.",
            "Successfully established trust with TPP.",
            "Error establishing trust with TPP",
            "pkcs11config trust",
            new String[]{
                "pkcs11config",
                "trust",
                "--force",
                "--hsmurl=" + tppConfig.getHsmUrl()
            },
            null);
    }

    private void invokePkcs11ConfigGetCertificate(PrintStream logger, Launcher launcher, FilePath ws,
        FilePath certChainFile)
        throws InterruptedException, IOException
    {
        invokeCommand(logger, launcher, ws,
            "Logging into TPP: configuring client: fetching certificate chain for '"
                + step.getCertLabel() + "'.",
            "Successfully fetched certificate chain.",
            "Error fetching certificate chain from TPP",
            "pkcs11config getcertificate",
            new String[]{
                "pkcs11config",
                "getcertificate",
                "--chainfile" + certChainFile.getRemote(),
                "--label=" + step.getCertLabel(),
            },
            null);
    }

    private void logoutTpp(PrintStream logger, FilePath ws, AgentInfo agentInfo) {
        if (!agentInfo.osType.isUnixCompatible()) {
            // TODO: remove credentials from Windows registry
            log(logger, "WARNING: TPP logout not yet implemented for Windows nodes");
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

        log(logger, "Logging out of TPP: deleting %s", libhsmtrust);
        try {
            deleteFileInterruptionSafe(libhsmtrust);
        } catch (InterruptedException e) {
            log(logger, "Error logging out of TPP: operation interrupted");
            e.printStackTrace(logger);
            return;
        } catch (Exception e) {
            log(logger, "Error logging out of TPP: %s", e.getMessage());
            e.printStackTrace(logger);
        }

        log(logger, "Logging out of TPP: deleting %s", libhsmconfig);
        try {
            libhsmconfig.delete();
        } catch (Exception e) {
            log(logger, "Error logging out of TPP: %s", e.getMessage());
            e.printStackTrace(logger);
        }
    }

    // Deletes the given FilePath. If the thread is interrupted, then it will
    // keep trying to delete the FilePath, and then re-throw the InterruptionException
    // afterwards. This method is useful if we really want to make sure that
    // the file is gone, even if we get interrupted ourselves.
    private void deleteFileInterruptionSafe(FilePath path)
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

    private void deleteFileOrPrintStackTrace(PrintStream logger, FilePath file) {
        try {
            if (file != null) {
                file.delete();
            }
        } catch (Exception e) {
            e.printStackTrace(logger);
        }
    }

    private String invokeCommand(PrintStream logger, Launcher launcher, FilePath ws,
        String preMessage, String successMessage, String errorMessage,
        String shortCommandLine, String[] cmdArgs, boolean[] masks)
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
        if (masks != null) {
            starter.masks(masks);
        }

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
            return output.toString("UTF-8");
        } else {
            log(logger,
                "%s: command exited with code %d. Output from command '%s' is as follows:\n%s",
                errorMessage, code, shortCommandLine, output.toString("UTF-8"));
            throw new IOException(errorMessage + ": command exited with code " + code);
        }
    }

    private void log(PrintStream logger, String format, Object... args) {
        logger.println("[" + step + "] " + String.format(format, args));
    }

    private void lock(PrintStream logger, FlowNode flowNode, Run<?, ?> run, String key)
        throws IOException, InterruptedException
    {
        flowNode.addAction(new PauseAction(Messages.JarSignerStep_functionName()));
        try {
            synchronized(locks) {
                String prevLockHolder;
                do {
                    log(logger, "Trying to acquire lock with key '%s'", key);
                    prevLockHolder = locks.putIfAbsent(key, run.toString());
                    if (prevLockHolder != null) {
                        log(logger, "Lock is already held by [%s], waiting...", prevLockHolder);
                        locks.wait();
                        log(logger, "Lock has been released. Trying again.");
                    }
                } while (prevLockHolder != null);
            }

            log(logger, "Lock successfully acquired.");
        } finally {
            PauseAction.endCurrentPause(flowNode);
        }
    }

    private void unlock(PrintStream logger, String key) {
        log(logger, "Releasing lock with key '%s'", key);
        synchronized(locks) {
            locks.remove(key);
            locks.notifyAll();
        }
    }

    private String calculateLockKey(Computer computer, Launcher launcher, AgentInfo agentInfo)
        throws IOException, InterruptedException
    {
        return getFqdn(computer, launcher, agentInfo) + ":" + agentInfo.username;
    }

    // Determines the FQDN of the given Computer.
    //
    // Computer.getHostName() (which does return an FQDN) isn't good enough and
    // sometimes fails to detect the hostname. So we fallback to invoking the
    // `hostname -f` command, but only on a Unix-compatible system.
    //
    // Never returns null. If the hostname cannot be determined, then returns
    // the empty string.
    private String getFqdn(Computer computer, Launcher launcher, AgentInfo agentInfo)
        throws IOException, InterruptedException
    {
        String result = computer.getHostName();
        if (result != null) {
            return result;
        }

        if (!agentInfo.osType.isUnixCompatible()) {
            return "";
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Launcher.ProcStarter starter =
            launcher.
            launch().
            cmds("hostname", "-f").
            stdout(output).
            quiet(true);

        Proc proc = starter.start();
        int code = proc.join();

        if (code == 0) {
            return output.toString("UTF-8").trim();
        } else {
            throw new IOException("Error determining node's FQDN: command 'hostname -f' exited with code " + code);
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
