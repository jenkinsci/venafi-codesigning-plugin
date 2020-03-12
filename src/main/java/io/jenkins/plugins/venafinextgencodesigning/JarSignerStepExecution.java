package io.jenkins.plugins.venafinextgencodesigning;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.jenkinsci.plugins.workflow.FilePathUtils;
import org.jenkinsci.plugins.workflow.graph.FlowNode;
import org.jenkinsci.plugins.workflow.steps.AbstractStepExecutionImpl;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.support.actions.PauseAction;
import org.jenkinsci.remoting.RoleChecker;

import hudson.FilePath;
import hudson.Platform;
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

        AgentInfo agentInfo = nodeRoot.act(new GetAgentInfo());

        String lockKey = calculateLockKey(wsComputer, agentInfo);
        return lock(logger, flowNode, run, lockKey, () -> {
            logger.println("Hello, world! server config count = " + PluginConfig.get().getTpmServerConfigs().size());
            logger.println("Current workspace = " + ws);
            logger.println("Node name = " + FilePathUtils.getNodeName(ws));
            getContext().onSuccess(null);
        });
    }

    @Override
    public void stop(Throwable cause) throws Exception {
        PrintStream logger = getContext().get(TaskListener.class).getLogger();
        logger.println("[" + step + "] Stopping...");

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
        MACOS,
        GENERIC_UNIX,
        WINDOWS;

        public boolean isUnixCompatible() {
            return this == MACOS || this == GENERIC_UNIX;
        }
    }

    public static final class AgentInfo implements Serializable {
        private static final long serialVersionUID = 1;

        public String username;
        public String home;
        public OsType osType;
    }

    public static final class GetAgentInfo implements FileCallable<AgentInfo> {
        private static final long serialVersionUID = 1;

        @Override
        public AgentInfo invoke(File nodeRoot, VirtualChannel virtualChannel) throws IOException, InterruptedException {
            AgentInfo info = new AgentInfo();
            info.username = System.getProperty("user.name");
            info.home = System.getProperty("user.home");
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
