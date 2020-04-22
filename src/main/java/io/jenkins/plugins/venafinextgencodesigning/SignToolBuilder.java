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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class SignToolBuilder extends Builder implements SimpleBuildStep {
    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private static transient LockManager LOCK_MANAGER = new LockManager();

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String tppName;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String fileOrGlob;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String subjectName;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String sha1;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String signatureDigestAlgos;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private boolean appendSignatures;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String timestampingServers;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String signToolInstallDir;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String venafiCodeSigningInstallDir;

    @DataBoundConstructor
    public SignToolBuilder() {
    }

    public String getTppName() {
        return tppName;
    }

    @DataBoundSetter
    public void setTppName(String value) {
        this.tppName = value;
    }

    public String getFileOrGlob() {
        return fileOrGlob;
    }

    @DataBoundSetter
    public void setFileOrGlob(String value) {
        this.fileOrGlob = value;
    }

    public String getSubjectName() {
        return subjectName;
    }

    @DataBoundSetter
    public void setSubjectName(String value) {
        if (value.equals("")) {
            this.subjectName = null;
        } else {
            this.subjectName = value;
        }
    }

    public String getSha1() {
        return sha1;
    }

    @DataBoundSetter
    public void setSha1(String value) {
        if (value.equals("")) {
            this.sha1 = null;
        } else {
            this.sha1 = value;
        }
    }

    public String getSignatureDigestAlgos() {
        return signatureDigestAlgos;
    }

    @DataBoundSetter
    public void setSignatureDigestAlgos(String value) {
        if (value.equals("")) {
            this.signatureDigestAlgos = null;
        } else {
            this.signatureDigestAlgos = value;
        }
    }

    public boolean getAppendSignatures() {
        return appendSignatures;
    }

    @DataBoundSetter
    public void setAppendSignatures(boolean value) {
        this.appendSignatures = value;
    }

    public String getTimestampingServers() {
        return timestampingServers;
    }

    @DataBoundSetter
    public void setTimestampingServers(String value) {
        this.timestampingServers = value;
    }

    public String getSignToolInstallDir() {
        return signToolInstallDir;
    }

    @DataBoundSetter
    public void setSignToolInstallDir(String value) {
        this.signToolInstallDir = value;
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
        Logger logger = new Logger(listener.getLogger(), Messages.SignToolBuilder_functionName());
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

        checkSubjectNameOrSha1Specified();

        String lockKey = calculateLockKey(wsComputer, launcher, agentInfo);
        LOCK_MANAGER.lock(logger, run, lockKey);
        try {
            loginTpp(logger, launcher, workspace, nodeRoot, run, agentInfo,
                tppConfig, credentials);
            invokeCspConfigSync(logger, launcher, workspace, agentInfo, nodeRoot);
            invokeSignTool(logger, launcher, workspace, agentInfo, nodeRoot);
        } finally {
            logoutTpp(logger, launcher, workspace, agentInfo, nodeRoot);
            LOCK_MANAGER.unlock(logger, lockKey);
        }
    }

    private void checkSubjectNameOrSha1Specified() throws AbortException {
        if (getSubjectName() == null && getSha1() == null) {
            throw new AbortException("Either the 'subjectName' or the 'sha1' parameter must be specified.");
        }
        if (getSubjectName() != null && getSha1() != null) {
            throw new AbortException("Either the 'subjectName' or the 'sha1' parameter must be specified,"
                + " but not both at the same time.");
        }
    }

    private String calculateLockKey(Computer computer, Launcher launcher, AgentInfo agentInfo)
        throws IOException, InterruptedException
    {
        return Utils.getFqdn(computer, launcher, agentInfo) + ":" + agentInfo.username;
    }

    private void loginTpp(Logger logger, Launcher launcher, FilePath ws, FilePath nodeRoot,
        Run<?, ?> run, AgentInfo agentInfo, TppConfig tppConfig,
        StandardUsernamePasswordCredentials credentials)
        throws InterruptedException, IOException, RuntimeException
    {
        FilePath cspConfigToolPath = getCspConfigToolPath(agentInfo, nodeRoot);
        CredentialsProvider.track(run, credentials);
        String password = Secret.toString(credentials.getPassword());
        invokeCommand(logger, launcher, ws,
            "Logging into TPP: configuring client: requesting grant from server.",
            "Successfully gotten grant from TPP.",
            "Error requesting grant from TPP",
            "cspconfig getgrant",
            false,
            new String[]{
                cspConfigToolPath.getRemote(),
                "getgrant",
                "-force",
                "-authurl:" + tppConfig.getAuthUrl(),
                "-hsmurl:" + tppConfig.getHsmUrl(),
                "-username:" + credentials.getUsername(),
                "-password:" + password
            },
            new boolean[] {
                false,
                false,
                false,
                false,
                false,
                false,
                true
            },
            null);
    }

    private void invokeCspConfigSync(Logger logger, Launcher launcher, FilePath ws,
        AgentInfo agentInfo, FilePath nodeRoot)
        throws InterruptedException, IOException, RuntimeException
    {
        FilePath cspConfigToolPath = getCspConfigToolPath(agentInfo, nodeRoot);
        invokeCommand(logger, launcher, ws,
            "Synchronizing local certificate store with TPP.",
            "Successfully synchronized local certificate store with TPP.",
            "Error synchronizing local certificate store with TPP",
            "cspconfig sync",
            false,
            new String[]{
                cspConfigToolPath.getRemote(),
                "sync"
            },
            null,
            null);
    }

    private void logoutTpp(Logger logger, Launcher launcher, FilePath ws,
        AgentInfo agentInfo, FilePath nodeRoot)
    {
        try {
            invokeCspConfigRevokeGrant(logger, launcher, ws, agentInfo, nodeRoot);
            return;
        } catch (InterruptedException e) {
            logger.log("Error logging out of TPP: operation interrupted.");
            return;
        } catch (Exception e) {
            // invokeCspConfigRevokeGrant() already logged a message.
            e.printStackTrace(logger.getOutput());
        }

        // Invoking 'cspconfig revokegrant' failed, so use a fallback
        // method to cleanup locally-stored credentials.
        logger.log("Logging out of TPP: deleting Venafi libhsm registry entry.");
        try {
            Utils.deleteWindowsRegistry(logger, launcher, "HKCU\\Software\\Venafi\\CSP");
        } catch (Exception e) {
            logger.log("Error logging out of TPP: %s", e.getMessage());
            e.printStackTrace(logger.getOutput());
        }
    }

    private void invokeCspConfigRevokeGrant(Logger logger, Launcher launcher, FilePath ws,
        AgentInfo agentInfo, FilePath nodeRoot)
        throws IOException, InterruptedException
    {
        FilePath cspConfigToolPath = getCspConfigToolPath(agentInfo, nodeRoot);
        invokeCommand(logger, launcher, ws,
            "Logging out of TPP: revoking server grant.",
            "Successfully revoked server grant.",
            "Error revoking grant from TPP",
            "cspconfig revokegrant",
            false,
            new String[]{
                cspConfigToolPath.getRemote(),
                "revokegrant",
                "-force",
            },
            null,
            null);
    }

    private void invokeSignTool(Logger logger, Launcher launcher, FilePath ws,
        AgentInfo agentInfo, FilePath nodeRoot)
        throws InterruptedException, IOException
    {
        FilePath signToolPath = getSignToolPath(agentInfo, nodeRoot);
        List<String> timestampingServersList = getTimestampingServersAsList();
        List<String> signatureDigestAlgos = getSignatureDigestAlgosAsList();

        // With this env var, when an error occurs at the Venafi CSP driver level,
        // that error is printed as part of the console output, instead of shown
        // in a dialog box that requires the user to click OK.
        Map<String, String> envs = new HashMap<String, String>();
        envs.put("VENAFICSPSilent", "1");

        int i = 0;
        for (String signatureDigestAlgo: signatureDigestAlgos) {
            ArrayList<String> cmdArgs = new ArrayList<String>();
            boolean shouldAppendSignature = getAppendSignatures();

            cmdArgs.add(signToolPath.getRemote());
            cmdArgs.add("sign");
            cmdArgs.add("/v");
            if (signatureDigestAlgo != null) {
                shouldAppendSignature = shouldAppendSignature || i > 0;
                cmdArgs.add("/fd");
                cmdArgs.add(signatureDigestAlgo);
            }
            if (!timestampingServersList.isEmpty()) {
                String timestampingServer = timestampingServersList.get(
                    (int) (Math.random() * timestampingServersList.size()));
                cmdArgs.add("/tr");
                cmdArgs.add(timestampingServer);
                if (signatureDigestAlgo != null) {
                    cmdArgs.add("/td");
                    cmdArgs.add(signatureDigestAlgo);
                }
            }
            if (shouldAppendSignature) {
                cmdArgs.add("/as");
            }
            if (getSubjectName() != null) {
                cmdArgs.add("/n");
                cmdArgs.add(getSubjectName());
            } else {
                cmdArgs.add("/sha1");
                cmdArgs.add(getSha1());
            }
            cmdArgs.add(getFileOrGlob());

            invokeCommand(logger, launcher, ws,
                "Signing with signtool: " + getFileOrGlob() + "",
                "Successfully signed '" + getFileOrGlob() + "'.",
                "Error signing '" + getFileOrGlob() + "'",
                "signtool",
                true,
                cmdArgs.toArray(new String[0]),
                null,
                envs);

            i++;
        }
    }

    private List<String> getSignatureDigestAlgosAsList() {
        List<String> result = new ArrayList<String>();
        if (signatureDigestAlgos != null) {
            for (String algo: signatureDigestAlgos.split("\\s+")) {
                result.add(algo);
            }
        } else {
            result.add(null);
        }
        return result;
    }

    private String invokeCommand(Logger logger, Launcher launcher, FilePath ws,
        String preMessage, String successMessage, String errorMessage,
        String shortCommandLine, boolean printOutputOnSuccess, String[] cmdArgs,
        boolean[] masks, Map<String, String> envs)
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

        String outputString = output.toString("UTF-8").trim();
        if (code == 0) {
            if (printOutputOnSuccess) {
                logger.log("%s", outputString);
            }
            logger.log("%s", successMessage);
            return outputString;
        } else {
            logger.log(
                "%s: command exited with code %d. Output from command '%s' is as follows:\n%s",
                errorMessage, code, shortCommandLine, outputString);
            throw new AbortException(errorMessage + ": command exited with code " + code);
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

    private FilePath detectVenafiCodeSigningInstallDir(FilePath nodeRoot) {
        if (getVenafiCodeSigningInstallDir() != null) {
            return nodeRoot.child(getVenafiCodeSigningInstallDir());
        } else {
            String programFiles = System.getenv("ProgramFiles");
            if (programFiles == null) {
                programFiles = "C:\\Program Files";
            }
            return nodeRoot.child(programFiles).child("Venafi");
        }
    }

    private FilePath getCspConfigToolPath(AgentInfo agentInfo, FilePath nodeRoot) {
        String cspConfigExe = agentInfo.isWindows64Bit ? "CSPConfig.exe" : "CSPConfig-x86.exe";
        FilePath toolsDir = detectVenafiCodeSigningInstallDir(nodeRoot);
        return toolsDir.child("PKCS11").child(cspConfigExe);
    }

    private FilePath getSignToolPath(AgentInfo agentInfo, FilePath nodeRoot) {
        String arch = agentInfo.isWindows64Bit ? "x64" : "x86";
        return nodeRoot.child(getSignToolInstallDir()).child(arch).child("signtool.exe");
    }

    @Symbol("venafiCodeSignWithSignTool")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        @SuppressWarnings("rawtypes")
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return Messages.SignToolBuilder_displayName();
        }

        public ListBoxModel doFillTppNameItems() {
            ListBoxModel items = new ListBoxModel();
            for (TppConfig config : PluginConfig.get().getTppConfigs()) {
                items.add(config.getName(), config.getName());
            }
            return items;
        }

        public FormValidation doCheckFileOrGlob(@QueryParameter String value) {
            return FormValidation.validateRequired(value);
        }

        public FormValidation doCheckSignToolInstallDir(@QueryParameter String value) {
            return FormValidation.validateRequired(value);
        }
    }

}
