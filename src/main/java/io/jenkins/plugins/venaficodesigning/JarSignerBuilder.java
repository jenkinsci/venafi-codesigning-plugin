package io.jenkins.plugins.venaficodesigning;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import jenkins.tasks.SimpleBuildStep;

import org.apache.commons.lang.RandomStringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class JarSignerBuilder extends Builder implements SimpleBuildStep {
    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String tppName;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String file;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String glob;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String certLabel;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String timestampingServers;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String extraArgs;

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

    public String getTimestampingServers() {
        return timestampingServers;
    }

    @DataBoundSetter
    public void setTimestampingServers(String value) {
        this.timestampingServers = value;
    }

    public String getExtraArgs() {
        return extraArgs;
    }

    @DataBoundSetter
    public void setExtraArgs(String value) {
        this.extraArgs = value;
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

        TppConfig tppConfig = getTppConfigByName(getTppName());
        if (tppConfig == null) {
            throw new AbortException("No Venafi TPP configuration with name '"
                + getTppName() + "' found");
        }

        StandardUsernamePasswordCredentials credentials = findCredentials(tppConfig);
        if (credentials == null) {
            throw new AbortException("No credentials with ID '"
                + tppConfig.getCredentialsId() + "' found");
        }

        checkFileOrGlobSpecified();

        String sessionID = RandomStringUtils.random(24, true, true);
        AgentInfo agentInfo = nodeRoot.act(new AgentInfo.GetAgentInfo());
        logger.log("Session ID: %s", sessionID);
        logger.log("Detected node info: %s", agentInfo);

        FilePath pkcs11ProviderConfigFile = null;
        try {
            Collection<FilePath> filesToSign = getFilesToSign(workspace);
            pkcs11ProviderConfigFile = workspace.createTempFile("pkcs11-provider", ".conf");

            Utils.createPkcs11ProviderConfig(agentInfo, nodeRoot, pkcs11ProviderConfigFile,
                getVenafiCodeSigningInstallDir());
            loginTpp(logger, launcher, workspace, nodeRoot, run, sessionID, agentInfo,
                tppConfig, credentials);
            invokeJarSigner(logger, launcher, workspace, sessionID, agentInfo,
                pkcs11ProviderConfigFile, filesToSign);
        } finally {
            logoutTpp(logger, launcher, workspace, nodeRoot, sessionID, agentInfo);
            Utils.deleteFileOrPrintStackTrace(logger, pkcs11ProviderConfigFile);
        }
    }

    TppConfig getTppConfigByName(String name) {
        return PluginConfig.get().getTppConfigByName(name);
    }

    StandardUsernamePasswordCredentials findCredentials(TppConfig tppConfig) {
        return Utils.findCredentials(tppConfig.getCredentialsId());
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

    private void loginTpp(Logger logger, Launcher launcher, FilePath ws,
        FilePath nodeRoot, Run<?, ?> run, String sessionID, AgentInfo agentInfo,
        TppConfig tppConfig, StandardUsernamePasswordCredentials credentials)
        throws InterruptedException, IOException, RuntimeException
    {
        invokePkcs11ConfigGetGrant(logger, launcher, ws, nodeRoot, run, tppConfig,
            sessionID, agentInfo, credentials);
    }

    private void invokePkcs11ConfigGetGrant(Logger logger, Launcher launcher, FilePath ws,
        FilePath nodeRoot, Run<?, ?> run, TppConfig tppConfig, String sessionID,
        AgentInfo agentInfo, StandardUsernamePasswordCredentials credentials)
        throws InterruptedException, IOException
    {
        FilePath pkcs11ConfigToolPath = getPkcs11ConfigToolPath(agentInfo, nodeRoot);
        CredentialsProvider.track(run, credentials);
        String password = Secret.toString(credentials.getPassword());

        Map<String, String> envs = new HashMap<String, String>();
        envs.put("LIBHSMINSTANCE", sessionID);

        invokeCommand(logger, launcher, ws,
            "Logging into TPP: configuring client: requesting grant from server.",
            "Successfully obtained grant from TPP.",
            "Error requesting grant from TPP",
            "pkcs11config getgrant",
            new String[]{
                pkcs11ConfigToolPath.getRemote(),
                "getgrant",
                "--force",
                "--authurl=" + tppConfig.getAuthUrl(),
                "--hsmurl=" + tppConfig.getHsmUrl(),
                "--username=" + credentials.getUsername(),
                "--password",
                password
            },
            new boolean[] {
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                true
            },
            envs);
    }

    private void logoutTpp(Logger logger, Launcher launcher, FilePath ws, FilePath nodeRoot,
        String sessionID, AgentInfo agentInfo)
    {
        try {
            invokePkcs11ConfigRevokeGrant(logger, launcher, ws, nodeRoot,
                sessionID, agentInfo);
        } catch (InterruptedException e) {
            logger.log("Error logging out of TPP: operation interrupted.");
        } catch (Exception e) {
            // invokePkcs11ConfigRevokeGrant() already logged a message.
            e.printStackTrace(logger.getOutput());
        }
    }

    private void invokePkcs11ConfigRevokeGrant(Logger logger, Launcher launcher, FilePath ws,
        FilePath nodeRoot, String sessionID, AgentInfo agentInfo)
        throws IOException, InterruptedException
    {
        FilePath pkcs11ConfigToolPath = getPkcs11ConfigToolPath(agentInfo, nodeRoot);

        Map<String, String> envs = new HashMap<String, String>();
        envs.put("LIBHSMINSTANCE", sessionID);

        invokeCommand(logger, launcher, ws,
            "Logging out of TPP: revoking server grant.",
            "Successfully revoked server grant.",
            "Error revoking grant from TPP",
            "pkcs11config revokegrant",
            new String[]{
                pkcs11ConfigToolPath.getRemote(),
                "revokegrant",
                "-force",
                "-clear",
            },
            null,
            envs);
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
        String sessionID, AgentInfo agentInfo, FilePath pkcs11ProviderConfigFile,
        Collection<FilePath> filesToSign)
        throws InterruptedException, IOException
    {
        List<String> timestampingServersList = getTimestampingServersAsList();

        Map<String, String> envs = new HashMap<String, String>();
        envs.put("LIBHSMINSTANCE", sessionID);

        for (FilePath fileToSign: filesToSign) {
            ArrayList<String> cmdArgs = new ArrayList<String>();
            cmdArgs.add("jarsigner");
            cmdArgs.add("-verbose");
            cmdArgs.add("-keystore");
            cmdArgs.add("NONE");
            cmdArgs.add("-storetype");
            cmdArgs.add("PKCS11");
            cmdArgs.add("-storepass");
            cmdArgs.add("none");
            cmdArgs.add("-providerclass");
            cmdArgs.add("sun.security.pkcs11.SunPKCS11");
            cmdArgs.add("-providerArg");
            cmdArgs.add(pkcs11ProviderConfigFile.getRemote());
            cmdArgs.add("-certs");
            if (!timestampingServersList.isEmpty()) {
                String timestampingServer = timestampingServersList.get(
                    (int) (Math.random() * timestampingServersList.size()));
                cmdArgs.add("-tsa");
                cmdArgs.add(timestampingServer);
            }
            if (getExtraArgs() != null) {
                List<String> extraArgsList = Utils.parseStringAsNewlineDelimitedList(getExtraArgs());
                for (String extraArg: extraArgsList) {
                    cmdArgs.add(extraArg);
                }
            }
            cmdArgs.add(fileToSign.getRemote());
            cmdArgs.add(getCertLabel());

            invokeCommand(logger, launcher, ws,
                "Signing with jarsigner: " + fileToSign.getRemote() + "",
                "Successfully signed '" + fileToSign.getRemote() + "'.",
                "Error signing '" + fileToSign.getRemote() + "'",
                "jarsigner",
                cmdArgs.toArray(new String[0]),
                null,
                envs);
        }
    }

    private String invokeCommand(Logger logger, Launcher launcher, FilePath ws,
        String preMessage, String successMessage, String errorMessage,
        String shortCommandLine, String[] cmdArgs, boolean[] masks,
        Map<String, String> envs)
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
        if (envs != null) {
            starter.envs(envs);
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

    private FilePath getPkcs11ConfigToolPath(AgentInfo agentInfo, FilePath nodeRoot) {
        FilePath toolsDir = Utils.detectVenafiCodeSigningInstallDir(agentInfo, nodeRoot,
            getVenafiCodeSigningInstallDir());
        if (agentInfo.osType == OsType.WINDOWS) {
            // The Venafi PKCS11 driver stores credentials in the Windows registry.
            // 32-bit and 64-bit executables have access to different Windows registry hives,
            // so we need to make sure that the architecture of pkcs11config.exe matches that
            // of jarsigner.exe.
            String exe = agentInfo.isJre64Bit ? "PKCS11Config.exe" : "PKCS11Config-x86.exe";
            return toolsDir.child("PKCS11").child(exe);
        } else {
            return toolsDir.child("bin").child("pkcs11config");
        }
    }

    private List<String> getTimestampingServersAsList() {
        List<String> result = new ArrayList<String>();
        if (getTimestampingServers() != null && !getTimestampingServers().isEmpty()) {
            for (String server: getTimestampingServers().split("\\s+")) {
                result.add(server);
            }
        }
        return result;
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
