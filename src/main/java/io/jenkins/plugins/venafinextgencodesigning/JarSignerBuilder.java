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
import java.util.ArrayList;
import java.util.Collection;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import jenkins.tasks.SimpleBuildStep;

import org.apache.commons.lang.StringEscapeUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class JarSignerBuilder extends Builder implements SimpleBuildStep {
    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private static transient LockManager LOCK_MANAGER = new LockManager();

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String tppName;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String file;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String glob;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String certLabel;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String venafiCodeSigningInstallDir;

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

    public String getFile() {
        return file;
    }

    @DataBoundSetter
    public void setFile(String value) {
        if (value.equals("")) {
            this.file = null;
        } else {
            this.file = value;
        }
    }

    public String getGlob() {
        return glob;
    }

    @DataBoundSetter
    public void setGlob(String value) {
        if (value.equals("")) {
            this.glob = null;
        } else {
            this.glob = value;
        }
    }

    public String getCertLabel() {
        return certLabel;
    }

    @DataBoundSetter
    public void setCertLabel(String value) {
        this.certLabel = value;
    }

    public String getVenafiCodeSigningInstallDir() {
        return venafiCodeSigningInstallDir;
    }

    @DataBoundSetter
    public void setVenafiCodeSigningInstallDir(String value) {
        if (value.equals("")) {
            this.venafiCodeSigningInstallDir = null;
        } else {
            this.venafiCodeSigningInstallDir = value;
        }
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener)
        throws InterruptedException, IOException
    {
        Logger logger = new Logger(listener.getLogger(), Messages.JarSignerBuilder_functionName());
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

        checkFileOrGlobSpecified();

        FilePath pkcs11ProviderConfigFile = null;
        FilePath certChainFile = null;

        String lockKey = calculateLockKey(wsComputer, launcher, agentInfo);
        LOCK_MANAGER.lock(logger, run, lockKey);
        try {
            Collection<FilePath> filesToSign = getFilesToSign(workspace);
            pkcs11ProviderConfigFile = workspace.createTempFile("pkcs11-provider", ".conf");
            certChainFile = workspace.createTempFile("venafi-certchain", ".crt");

            createPkcs11ProviderConfig(agentInfo, nodeRoot, pkcs11ProviderConfigFile);
            loginTpp(logger, launcher, workspace, nodeRoot, run, agentInfo, tppConfig,
                credentials, certChainFile);
            invokeJarSigner(logger, launcher, workspace, agentInfo,
                pkcs11ProviderConfigFile, certChainFile, filesToSign);
        } finally {
            logoutTpp(logger, launcher, workspace, agentInfo);
            LOCK_MANAGER.unlock(logger, lockKey);
            deleteFileOrPrintStackTrace(logger, pkcs11ProviderConfigFile);
            deleteFileOrPrintStackTrace(logger, certChainFile);
        }
    }

    private void checkFileOrGlobSpecified() throws AbortException {
        if (getFile() == null && getGlob() == null) {
            throw new AbortException("Either the 'file' or the 'glob' parameter must be specified.");
        }
        if (getFile() != null && getGlob() != null) {
            throw new AbortException("Either the 'file' or the 'glob' parameter must be specified,"
                + " but not both at the same time.");
        }
    }

    private String calculateLockKey(Computer computer, Launcher launcher, AgentInfo agentInfo)
        throws IOException, InterruptedException
    {
        return Utils.getFqdn(computer, launcher, agentInfo) + ":" + agentInfo.username;
    }

    private void createPkcs11ProviderConfig(AgentInfo agentInfo, FilePath nodeRoot, FilePath file)
        throws IOException, InterruptedException
    {
        String libpath = getPkcs11DriverLibraryPath(agentInfo, nodeRoot).getRemote();
        String contents = String.format(
            "name = VenafiPKCS11%n"
            + "library = \"%s\"%n"
            + "slot = 0%n",
            StringEscapeUtils.unescapeJava(libpath)
        );
        file.write(contents, "UTF-8");
    }

    private void loginTpp(Logger logger, Launcher launcher, FilePath ws,
        FilePath nodeRoot, Run<?, ?> run, AgentInfo agentInfo, TppConfig tppConfig,
        StandardUsernamePasswordCredentials credentials, FilePath certChainFile)
        throws InterruptedException, IOException, RuntimeException
    {
        invokePkcs11ConfigGetGrant(logger, launcher, ws, nodeRoot, run, tppConfig,
            agentInfo, credentials);
        invokePkcs11ConfigGetCertificate(logger, launcher, ws, nodeRoot, agentInfo,
            certChainFile);
    }

    private void invokePkcs11ConfigGetGrant(Logger logger, Launcher launcher, FilePath ws,
        FilePath nodeRoot, Run<?, ?> run, TppConfig tppConfig, AgentInfo agentInfo,
        StandardUsernamePasswordCredentials credentials)
        throws InterruptedException, IOException
    {
        FilePath pkcs11ConfigToolPath = getPkcs11ConfigToolPath(agentInfo, nodeRoot);
        CredentialsProvider.track(run, credentials);
        String password = Secret.toString(credentials.getPassword());
        invokeCommand(logger, launcher, ws,
            "Logging into TPP: configuring client: requesting grant from server.",
            "Successfully gotten grant from TPP.",
            "Error requesting grant from TPP",
            "pkcs11config getgrant",
            new String[]{
                pkcs11ConfigToolPath.getRemote(),
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

    private void invokePkcs11ConfigGetCertificate(Logger logger, Launcher launcher, FilePath ws,
        FilePath nodeRoot, AgentInfo agentInfo, FilePath certChainFile)
        throws InterruptedException, IOException
    {
        FilePath pkcs11ConfigToolPath = getPkcs11ConfigToolPath(agentInfo, nodeRoot);
        invokeCommand(logger, launcher, ws,
            "Logging into TPP: configuring client: fetching certificate chain for '"
                + getCertLabel() + "'.",
            "Successfully fetched certificate chain.",
            "Error fetching certificate chain from TPP",
            "pkcs11config getcertificate",
            new String[]{
                pkcs11ConfigToolPath.getRemote(),
                "getcertificate",
                "--chainfile=" + certChainFile.getRemote(),
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

    private Collection<FilePath> getFilesToSign(FilePath ws)
        throws IOException, InterruptedException
    {
        Collection<FilePath> result = new ArrayList<FilePath>();
        if (getFile() != null) {
            result.add(ws.child(getFile()));
        } else {
            for (FilePath path: ws.list(getGlob(), null, false)) {
                result.add(path);
            }
        }
        return result;
    }

    private void invokeJarSigner(Logger logger, Launcher launcher, FilePath ws,
        AgentInfo agentInfo, FilePath pkcs11ProviderConfigFile, FilePath certChainFile,
        Collection<FilePath> filesToSign)
        throws InterruptedException, IOException
    {
        for (FilePath fileToSign: filesToSign) {
            invokeCommand(logger, launcher, ws,
                "Signing with jarsigner: " + fileToSign.getRemote() + "",
                "Successfully signed '" + fileToSign.getRemote() + "'.",
                "Error signing '" + fileToSign.getRemote() + "'",
                "jarsigner",
                new String[]{
                    "jarsigner",
                    "-verbose",
                    "-keystore", "NONE",
                    "-storetype", "PKCS11",
                    "-storepass", "bogus",
                    "-providerclass", "sun.security.pkcs11.SunPKCS11",
                    "-providerArg", pkcs11ProviderConfigFile.getRemote(),
                    "-certs",
                    "-certchain", certChainFile.getRemote(),
                    fileToSign.getRemote(),
                    getCertLabel()
                },
                null);
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

    private FilePath detectVenafiCodeSigningInstallDir(AgentInfo agentInfo, FilePath nodeRoot) {
        if (getVenafiCodeSigningInstallDir() != null) {
            return nodeRoot.child(getVenafiCodeSigningInstallDir());
        } else if (agentInfo.osType == OsType.MACOS) {
            return nodeRoot.child("/Library/Venafi/CodeSigning");
        } else if (agentInfo.osType == OsType.WINDOWS) {
            String programFiles = System.getenv("ProgramFiles");
            if (programFiles == null) {
                programFiles = "C:\\Program Files";
            }
            return nodeRoot.child(programFiles).child("Venafi");
        } else {
            return nodeRoot.child("/opt/venafi/codesign");
        }
    }

    private FilePath getPkcs11ConfigToolPath(AgentInfo agentInfo, FilePath nodeRoot) {
        FilePath toolsDir = detectVenafiCodeSigningInstallDir(agentInfo, nodeRoot);
        if (agentInfo.osType == OsType.WINDOWS) {
            return toolsDir.child("PKCS11").child("PKCS11Config.exe");
        } else {
            return toolsDir.child("bin").child("pkcs11config");
        }
    }

    private FilePath getPkcs11DriverLibraryPath(AgentInfo agentInfo, FilePath nodeRoot) {
        FilePath toolsDir = detectVenafiCodeSigningInstallDir(agentInfo, nodeRoot);
        if (agentInfo.osType == OsType.WINDOWS) {
            return toolsDir.child("PKCS11").child("VenafiPkcs11.dll");
        } else {
            return toolsDir.child("lib").child("venafipkcs11.so");
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
            return Messages.JarSignerBuilder_displayName();
        }

        public ListBoxModel doFillTppNameItems() {
            ListBoxModel items = new ListBoxModel();
            for (TppConfig config : PluginConfig.get().getTppConfigs()) {
                items.add(config.getName(), config.getName());
            }
            return items;
        }

        public FormValidation doCheckCertLabel(@QueryParameter String value) {
            return FormValidation.validateRequired(value);
        }
    }

}
