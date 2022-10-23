package io.jenkins.plugins.venaficodesigning;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import hudson.Launcher;
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
import org.kohsuke.stapler.verb.POST;

public class JarSignerBuilder extends Builder implements SimpleBuildStep {
    private final String tppName;
    private final String certLabel;
    private final Credential credential;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String file;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String glob;


    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private List<TimestampingServer> timestampingServers = new ArrayList<>();

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private List<CmdArg> extraArgs = new ArrayList<>();

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String venafiClientToolsDir;

    @DataBoundConstructor
    public JarSignerBuilder(String tppName, String certLabel, Credential credential) {
        this.tppName = tppName;
        this.certLabel = certLabel;
        this.credential = credential;
    }

    public String getTppName() {
        return tppName;
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

    public Credential getCredential() {
        return credential;
    }

    public List<TimestampingServer> getTimestampingServers() {
        return timestampingServers;
    }

    @DataBoundSetter
    public void setTimestampingServers(List<TimestampingServer> value) {
        this.timestampingServers = value;
    }

    public List<CmdArg> getExtraArgs() {
        return extraArgs;
    }

    @DataBoundSetter
    public void setExtraArgs(List<CmdArg> value) {
        this.extraArgs = value;
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

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener)
        throws InterruptedException, IOException {
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

        StandardUsernamePasswordCredentials credentials = findCredentials(getCredential());

        String sessionID = RandomStringUtils.random(24, true, true);
        AgentInfo agentInfo = nodeRoot.act(new AgentInfo.GetAgentInfo());
        logger.log("Session ID: %s", sessionID);
        logger.log("Detected node info: %s", agentInfo);

        FilePath pkcs11ProviderConfigFile = null;
        try {
            Collection<FilePath> filesToSign = getFilesToSign(workspace);
            pkcs11ProviderConfigFile = workspace.createTempFile("pkcs11-provider", ".conf");

            Utils.createPkcs11ProviderConfig(launcher, agentInfo, nodeRoot,
                pkcs11ProviderConfigFile, getVenafiClientToolsDir());
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

    StandardUsernamePasswordCredentials findCredentials(Credential credential) {
        return Utils.findCredentials(credential.getCredentialsId());
    }

    private void loginTpp(Logger logger, Launcher launcher, FilePath ws,
                          FilePath nodeRoot, Run<?, ?> run, String sessionID, AgentInfo agentInfo,
                          TppConfig tppConfig, StandardUsernamePasswordCredentials credentials)
        throws InterruptedException, IOException, RuntimeException {
        invokePkcs11ConfigGetGrant(logger, launcher, ws, nodeRoot, run, tppConfig,
            sessionID, agentInfo, credentials);
    }

    private void invokePkcs11ConfigGetGrant(Logger logger, Launcher launcher, FilePath ws,
                                            FilePath nodeRoot, Run<?, ?> run, TppConfig tppConfig, String sessionID,
                                            AgentInfo agentInfo, StandardUsernamePasswordCredentials credentials)
        throws InterruptedException, IOException {
        FilePath pkcs11ConfigToolPath = Utils.getPkcs11ConfigToolPath(launcher, agentInfo,
            nodeRoot, getVenafiClientToolsDir());
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
            new boolean[]{
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
                           String sessionID, AgentInfo agentInfo) {
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
        throws IOException, InterruptedException {
        FilePath pkcs11ConfigToolPath = Utils.getPkcs11ConfigToolPath(launcher, agentInfo,
            nodeRoot, getVenafiClientToolsDir());

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
        throws IOException, InterruptedException {
        Collection<FilePath> result = new ArrayList<FilePath>();
        if (getFile() != null) {
            result.add(ws.child(getFile()));
        } else {
            for (FilePath path : ws.list(getGlob(), null, false)) {
                result.add(path);
            }
        }
        return result;
    }

    private void invokeJarSigner(Logger logger, Launcher launcher, FilePath ws,
                                 String sessionID, AgentInfo agentInfo, FilePath pkcs11ProviderConfigFile,
                                 Collection<FilePath> filesToSign)
        throws InterruptedException, IOException {
        Map<String, String> envs = new HashMap<String, String>();
        envs.put("LIBHSMINSTANCE", sessionID);

        for (FilePath fileToSign : filesToSign) {
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
            if (!getTimestampingServers().isEmpty()) {
                TimestampingServer timestampingServer = getTimestampingServers().get(
                    (int) (Math.random() * getTimestampingServers().size()));
                cmdArgs.add("-tsa");
                cmdArgs.add(timestampingServer.getAddress());
            }
            for (CmdArg extraArg : getExtraArgs()) {
                cmdArgs.add(extraArg.getArgument());
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
        throws InterruptedException, IOException {
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

        int code;
        try {
            code = startAndJoinProc(starter);
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

    int startAndJoinProc(Launcher.ProcStarter starter) throws IOException, InterruptedException {
        return starter.start().join();
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

        public FormValidation doCheckFile(@QueryParameter String value,
                                          @QueryParameter String glob) {
            if (glob.isEmpty()) {
                return FormValidation.validateRequired(value);
            } else if (!value.isEmpty()) {
                return FormValidation.error(Messages.JarSignerBuilder_fileAndGlobMutuallyExclusive());
            } else {
                return FormValidation.ok();
            }
        }

        public FormValidation doCheckGlob(@QueryParameter String value,
                                          @QueryParameter String file) {
            if (file.isEmpty()) {
                return FormValidation.validateRequired(value);
            } else if (!value.isEmpty()) {
                return FormValidation.error(Messages.JarSignerBuilder_fileAndGlobMutuallyExclusive());
            } else {
                return FormValidation.ok();
            }
        }

        public FormValidation doCheckCertLabel(@QueryParameter String value) {
            return FormValidation.validateRequired(value);
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

    }

}
