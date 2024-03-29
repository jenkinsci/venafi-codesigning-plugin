package io.jenkins.plugins.venaficodesigning;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import hudson.Launcher;
import hudson.Proc;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.AbstractProject;
import hudson.model.Computer;
import hudson.model.Item;
import hudson.model.Node;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import hudson.tasks.BuildStepDescriptor;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import jenkins.tasks.SimpleBuildStep;

import org.apache.commons.lang.RandomStringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.kohsuke.stapler.verb.POST;

public class SignToolVerifyBuilder extends Builder implements SimpleBuildStep {
    private final String tppName;
    private final String fileOrGlob;

    private final Credential credential;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String signToolPath;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String venafiClientToolsDir;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private boolean useMachineConfiguration;

    @DataBoundConstructor
    public SignToolVerifyBuilder(String tppName, String fileOrGlob, Credential credential) {
        this.tppName = tppName;
        this.fileOrGlob = fileOrGlob;
        this.credential = credential;
    }

    public String getTppName() {
        return tppName;
    }

    public String getFileOrGlob() {
        return fileOrGlob;
    }

    public String getSignToolPath() {
        return signToolPath;
    }

    public Credential getCredential() {
        return credential;
    }

    @DataBoundSetter
    public void setSignToolPath(String value) {
        if (value.equals("")) {
            this.signToolPath = null;
        } else {
            this.signToolPath = value;
        }
    }

    public String getVenafiClientToolsDir() {
        return venafiClientToolsDir;
    }

    @DataBoundSetter
    public void setVenafiClientToolsDir(String value) {
        if (value.equals("")) {
            this.venafiClientToolsDir = null;
        } else {
            this.venafiClientToolsDir = value;
        }
    }

    public boolean getUseMachineConfiguration() {
        return useMachineConfiguration;
    }

    @DataBoundSetter
    public void setUseMachineConfiguration(boolean value) {
        this.useMachineConfiguration = value;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener)
        throws InterruptedException, IOException
    {
        Logger logger = new Logger(listener.getLogger(), Messages.JarSignerVerifyBuilder_functionName());
        Computer wsComputer = getComputer(workspace);
        Node wsNode = getNode(wsComputer);
        FilePath nodeRoot = getNodeRoot(wsNode);

        TppConfig tppConfig = PluginConfig.get().getTppConfigByName(getTppName());
        if (tppConfig == null) {
            throw new AbortException("No Venafi TPP configuration with name '"
                + getTppName() + "' found");
        }

        StandardUsernamePasswordCredentials credentials = findCredentialsById(credential, run);
        if (credentials == null) {
            throw new AbortException("No credentials with ID '"
                + credential.getCredentialsId() + "' found");
        }

        String sessionID = RandomStringUtils.random(24, true, true);
        AgentInfo agentInfo = nodeRoot.act(new AgentInfo.GetAgentInfo());
        logger.log("Session ID: %s", sessionID);
        logger.log("Detected node info: %s", agentInfo);

        try {
            loginTpp(logger, launcher, workspace, nodeRoot, run, sessionID,
                agentInfo, tppConfig, credentials);
            invokeCspConfigSync(logger, launcher, workspace, sessionID,
                agentInfo, nodeRoot);
            invokeSignToolVerify(logger, launcher, workspace, sessionID,
                agentInfo, nodeRoot);
        } finally {
            logoutTpp(logger, launcher, workspace, sessionID,
                agentInfo, nodeRoot);
        }
    }

    private Computer getComputer(FilePath workspace) throws AbortException {
        Computer result = workspace.toComputer();
        if (result == null) {
            throw new AbortException("Unable to retrieve computer for workspace");
        }
        return result;
    }

    private Node getNode(Computer computer) throws AbortException {
        Node result = computer.getNode();
        if (result == null) {
            throw new AbortException("Unable to retrieve node for workspace");
        }
        return result;
    }

    private FilePath getNodeRoot(Node node) throws AbortException {
        FilePath result = node.getRootPath();
        if (result == null) {
            throw new AbortException("Unable to retrieve root path of node");
        }
        return result;
    }

    StandardUsernamePasswordCredentials findCredentialsById(Credential credential, Run<?,?> run) {
        return Utils.findCredentialsById(credential.getCredentialsId(), run);
    }

    private void loginTpp(Logger logger, Launcher launcher, FilePath ws, FilePath nodeRoot,
        Run<?, ?> run, String sessionID, AgentInfo agentInfo, TppConfig tppConfig,
        StandardUsernamePasswordCredentials credentials)
        throws InterruptedException, IOException, RuntimeException
    {
        FilePath cspConfigToolPath = Utils.getCspConfigToolPath(launcher, agentInfo,
            nodeRoot, getVenafiClientToolsDir());
        CredentialsProvider.track(run, credentials);
        String password = Secret.toString(credentials.getPassword());

        ArrayList<String> cmdArgs = new ArrayList<String>();
        cmdArgs.add(cspConfigToolPath.getRemote());
        cmdArgs.add("getgrant");
        if (getUseMachineConfiguration()) {
            cmdArgs.add("-machine");
        }
        cmdArgs.add("-force");
        cmdArgs.add("-authurl:" + tppConfig.getAuthUrl());
        cmdArgs.add("-hsmurl:" + tppConfig.getHsmUrl());
        cmdArgs.add("-username:" + credentials.getUsername());
        cmdArgs.add("-password");
        cmdArgs.add(password);

        boolean[] masks = new boolean[cmdArgs.size()];
        for (int i = 0; i < cmdArgs.size() - 1; i++) {
            masks[i] = false;
        }
        masks[cmdArgs.size() - 1] = true;

        Map<String, String> envs = new HashMap<String, String>();
        envs.put("LIBHSMINSTANCE", sessionID);

        invokeCommand(logger, launcher, ws,
            "Logging into TPP: configuring client: requesting grant from server.",
            "Successfully obtained grant from TPP.",
            "Error requesting grant from TPP",
            "cspconfig getgrant",
            false,
            cmdArgs.toArray(new String[0]),
            masks,
            envs);
    }

    private void invokeCspConfigSync(Logger logger, Launcher launcher, FilePath ws,
        String sessionID, AgentInfo agentInfo, FilePath nodeRoot)
        throws InterruptedException, IOException, RuntimeException
    {
        FilePath cspConfigToolPath = Utils.getCspConfigToolPath(launcher, agentInfo,
            nodeRoot, getVenafiClientToolsDir());

        ArrayList<String> cmdArgs = new ArrayList<String>();
        cmdArgs.add(cspConfigToolPath.getRemote());
        cmdArgs.add("sync");
        if (getUseMachineConfiguration()) {
            cmdArgs.add("-machine");
        }

        Map<String, String> envs = new HashMap<String, String>();
        envs.put("LIBHSMINSTANCE", sessionID);

        invokeCommand(logger, launcher, ws,
            "Synchronizing local certificate store with TPP.",
            "Successfully synchronized local certificate store with TPP.",
            "Error synchronizing local certificate store with TPP",
            "cspconfig sync",
            false,
            cmdArgs.toArray(new String[0]),
            null,
            envs);
    }

    private void invokeSignToolVerify(Logger logger, Launcher launcher, FilePath ws,
        String sessionID, AgentInfo agentInfo, FilePath nodeRoot)
        throws InterruptedException, IOException
    {
        String signToolPath = Utils.getSignToolPath(getSignToolPath());

        Map<String, String> envs = new HashMap<String, String>();
        // With this env var, when an error occurs at the Venafi CSP driver level,
        // that error is printed as part of the console output, instead of shown
        // in a dialog box that requires the user to click OK.
        envs.put("VENAFICSPSilent", "1");
        envs.put("LIBHSMINSTANCE", sessionID);

        invokeCommand(logger, launcher, ws,
            "Verifying with signtool: " + getFileOrGlob() + "",
            "Successfully verifying '" + getFileOrGlob() + "'.",
            "Error verifying '" + getFileOrGlob() + "'",
            "signtool",
            true,
            new String[]{
                signToolPath,
                "verify",
                "/pa",
                getFileOrGlob(),
            },
            null,
            envs);
    }

    private void logoutTpp(Logger logger, Launcher launcher, FilePath ws,
        String sessionID, AgentInfo agentInfo, FilePath nodeRoot)
    {
        try {
            invokeCspConfigRevokeGrant(logger, launcher, ws, sessionID,
                agentInfo, nodeRoot);
        } catch (InterruptedException e) {
            logger.log("Error logging out of TPP: operation interrupted.");
        } catch (Exception e) {
            // invokeCspConfigRevokeGrant() already logged a message.
            e.printStackTrace(logger.getOutput());
        }
    }

    private void invokeCspConfigRevokeGrant(Logger logger, Launcher launcher, FilePath ws,
        String sessionID, AgentInfo agentInfo, FilePath nodeRoot)
        throws IOException, InterruptedException
    {
        FilePath cspConfigToolPath = Utils.getCspConfigToolPath(launcher, agentInfo,
            nodeRoot, getVenafiClientToolsDir());

        ArrayList<String> cmdArgs = new ArrayList<String>();
        cmdArgs.add(cspConfigToolPath.getRemote());
        cmdArgs.add("revokegrant");
        if (getUseMachineConfiguration()) {
            cmdArgs.add("-machine");
        }
        cmdArgs.add("-force");
        cmdArgs.add("-clear");

        Map<String, String> envs = new HashMap<String, String>();
        envs.put("LIBHSMINSTANCE", sessionID);

        invokeCommand(logger, launcher, ws,
            "Logging out of TPP: revoking server grant.",
            "Successfully revoked server grant.",
            "Error revoking grant from TPP",
            "cspconfig revokegrant",
            false,
            cmdArgs.toArray(new String[0]),
            null,
            envs);
    }

    private String invokeCommand(Logger logger, Launcher launcher, FilePath ws,
        String preMessage, String successMessage, String errorMessage,
        String shortCommandLine,  boolean printOutputOnSuccess, String[] cmdArgs,
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

    @Symbol("venafiVerifyWithSignTool")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        @SuppressWarnings("rawtypes")
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return Messages.SignToolVerifyBuilder_displayName();
        }

        public ListBoxModel doFillTppNameItems() {
            ListBoxModel items = new ListBoxModel();
            for (TppConfig config : PluginConfig.get().getTppConfigs()) {
                items.add(config.getName(), config.getName());
            }
            return items;
        }

        @POST
        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String credentialsId) {
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                    && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                .includeMatchingAs(ACL.SYSTEM,
                    item,
                    StandardCredentials.class,
                    new ArrayList<>(),
                    CredentialsMatchers.anyOf(
					    CredentialsMatchers.instanceOf(StandardUsernamePasswordCredentials.class),
					    CredentialsMatchers.instanceOf(UsernamePasswordCredentials.class))
                )
                .includeCurrentValue(credentialsId);
        }

        public FormValidation doCheckFileOrGlob(@QueryParameter String value) {
            return FormValidation.validateRequired(value);
        }
    }
}
