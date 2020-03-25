package io.jenkins.plugins.venafinextgencodesigning;

import hudson.Launcher;
import hudson.Proc;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.AbstractProject;
import hudson.model.Computer;
import hudson.model.Node;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import hudson.tasks.BuildStepDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

public class JarSignerBuilder extends Builder implements SimpleBuildStep {
    private static transient LockManager LOCK_MANAGER = new LockManager();

    private String tppName;
    private String jarFile;
    private String certLabel;

    @DataBoundConstructor
    public JarSignerBuilder() {
    }

    public String getTppName() {
        return tppName;
    }

    @DataBoundSetter
    public void setTppName(String value) {
        this.tppName = value;
    }

    public String getJarFile() {
        return jarFile;
    }

    @DataBoundSetter
    public void setJarFile(String value) {
        this.jarFile = value;
    }

    public String getCertLabel() {
        return certLabel;
    }

    @DataBoundSetter
    public void setCertLabel(String value) {
        this.certLabel = value;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener)
        throws InterruptedException, IOException
    {
        Logger logger = new Logger(listener.getLogger(), Messages.JarSignerStep_functionName());
        Computer wsComputer = workspace.toComputer();
        if (wsComputer == null) {
            throw new AbortException("Unable to retrieve computer for workspace");
        }
        Node wsNode = wsComputer.getNode();
        if (wsNode == null) {
            throw new AbortException("Unable to retrieve node for workspace");
        }
        FilePath nodeRoot = wsNode.getRootPath();
        if (nodeRoot == null) {
            throw new AbortException("Unable to retrieve root path of node");
        }

        TppConfig tppConfig = PluginConfig.get().getTppConfigByName(getTppName());
        if (tppConfig == null) {
            throw new AbortException("No Venafi TPP configuration with name '"
                + getTppName() + "' found");
        }

        StandardUsernamePasswordCredentials credentials = Utils.findCredentials(
            tppConfig.getCredentialsId());
        if (credentials == null) {
            throw new AbortException("No credentials with ID '"
                + tppConfig.getCredentialsId() + "' found");
        }

        AgentInfo agentInfo = nodeRoot.act(new AgentInfo.GetAgentInfo());
        logger.log("Detected OS: %s", agentInfo.osType);

        FilePath certChainFile = null;

        String lockKey = calculateLockKey(wsComputer, launcher, agentInfo);
        LOCK_MANAGER.lock(logger, run, lockKey);
        try {
            certChainFile = workspace.createTempFile("venafi-certchain", "crt");

            loginTpp(logger, launcher, workspace, run, agentInfo, tppConfig,
                credentials, certChainFile);
            //invokeJarSigner(logger);
        } finally {
            logoutTpp(logger, launcher, workspace, agentInfo);
            LOCK_MANAGER.unlock(logger, lockKey);
            deleteFileOrPrintStackTrace(logger, certChainFile);
        }
    }

    private String calculateLockKey(Computer computer, Launcher launcher, AgentInfo agentInfo)
        throws IOException, InterruptedException
    {
        return Utils.getFqdn(computer, launcher, agentInfo) + ":" + agentInfo.username;
    }

    private void loginTpp(Logger logger, Launcher launcher, FilePath ws,
        Run<?, ?> run, AgentInfo agentInfo, TppConfig tppConfig,
        StandardUsernamePasswordCredentials credentials, FilePath certChainFile)
        throws InterruptedException, IOException, RuntimeException
    {
        invokePkcs11ConfigGetGrant(logger, launcher, ws, run, tppConfig, credentials);
        invokePkcs11ConfigTrust(logger, launcher, ws, tppConfig);
        invokePkcs11ConfigGetCertificate(logger, launcher, ws, certChainFile);
    }

    private void invokePkcs11ConfigGetGrant(Logger logger, Launcher launcher, FilePath ws,
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

    private void invokePkcs11ConfigTrust(Logger logger, Launcher launcher, FilePath ws,
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

    private void invokePkcs11ConfigGetCertificate(Logger logger, Launcher launcher, FilePath ws,
        FilePath certChainFile)
        throws InterruptedException, IOException
    {
        invokeCommand(logger, launcher, ws,
            "Logging into TPP: configuring client: fetching certificate chain for '"
                + getCertLabel() + "'.",
            "Successfully fetched certificate chain.",
            "Error fetching certificate chain from TPP",
            "pkcs11config getcertificate",
            new String[]{
                "pkcs11config",
                "getcertificate",
                "--chainfile" + certChainFile.getRemote(),
                "--label=" + getCertLabel(),
            },
            null);
    }

    private void logoutTpp(Logger logger, Launcher launcher, FilePath ws, AgentInfo agentInfo) {
        if (!agentInfo.osType.isUnixCompatible()) {
            logger.log("Logging out of TPP: deleting Venafi libhsm registry entry.");
            try {
                Utils.deleteWindowsRegistry(logger, launcher, "HKCU\\Software\\Venafi\\libhsm");
            } catch (Exception e) {
                e.printStackTrace(logger.getOutput());
            }
            return;
        }

        FilePath home;
        try {
            home = FilePath.getHomeDirectory(ws.getChannel());
        } catch (Exception e) {
            e.printStackTrace(logger.getOutput());
            return;
        }

        FilePath libhsmtrust = home.child(".libhsmtrust");
        FilePath libhsmconfig = home.child(".libhsmconfig");

        logger.log("Logging out of TPP: deleting %s", libhsmtrust);
        try {
            deleteFileInterruptionSafe(libhsmtrust);
        } catch (InterruptedException e) {
            logger.log("Error logging out of TPP: operation interrupted");
            e.printStackTrace(logger.getOutput());
            return;
        } catch (Exception e) {
            logger.log("Error logging out of TPP: %s", e.getMessage());
            e.printStackTrace(logger.getOutput());
        }

        logger.log("Logging out of TPP: deleting %s", libhsmconfig);
        try {
            libhsmconfig.delete();
        } catch (Exception e) {
            logger.log("Error logging out of TPP: %s", e.getMessage());
            e.printStackTrace(logger.getOutput());
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

    private void deleteFileOrPrintStackTrace(Logger logger, FilePath file) {
        try {
            if (file != null) {
                file.delete();
            }
        } catch (Exception e) {
            e.printStackTrace(logger.getOutput());
        }
    }

    private String invokeCommand(Logger logger, Launcher launcher, FilePath ws,
        String preMessage, String successMessage, String errorMessage,
        String shortCommandLine, String[] cmdArgs, boolean[] masks)
        throws InterruptedException, IOException
    {
        logger.log("%s", preMessage);

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
            logger.log("%s: %s", errorMessage, e.getMessage());
            throw e;
        }

        if (code == 0) {
            logger.log("%s", successMessage);
            return output.toString("UTF-8");
        } else {
            logger.log(
                "%s: command exited with code %d. Output from command '%s' is as follows:\n%s",
                errorMessage, code, shortCommandLine, output.toString("UTF-8"));
            throw new AbortException(errorMessage + ": command exited with code " + code);
        }
    }

    @Symbol("venafiCodeSignWithJarSigner")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        @SuppressWarnings("rawtypes")
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return Messages.JarSignerStep_displayName();
        }

        public ListBoxModel doFillTppNameItems() {
            ListBoxModel items = new ListBoxModel();
            for (TppConfig config : PluginConfig.get().getTppConfigs()) {
                items.add(config.getName(), config.getName());
            }
            return items;
        }

        public FormValidation doCheckJarFile(@QueryParameter String value) {
            return FormValidation.validateRequired(value);
        }

        public FormValidation doCheckCertLabel(@QueryParameter String value) {
            return FormValidation.validateRequired(value);
        }
    }

}
