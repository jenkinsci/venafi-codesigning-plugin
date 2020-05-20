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

public class JarSignerVerifyBuilder extends Builder implements SimpleBuildStep {
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
    public JarSignerVerifyBuilder() {
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

        String sessionID = RandomStringUtils.random(24, true, true);
        AgentInfo agentInfo = nodeRoot.act(new AgentInfo.GetAgentInfo());
        logger.log("Session ID: %s", sessionID);
        logger.log("Detected node info: %s", agentInfo);

        FilePath tempDir = null;
        try {
            tempDir = workspace.createTempDir("jarsigner-verify", "");

            Collection<FilePath> filesToVerify = getFilesToVerify(workspace);
            FilePath certFile = tempDir.child("cert.crt");
            FilePath chainFile = tempDir.child("chain.crt");
            FilePath keystore = tempDir.child("keystore");

            loginTpp(logger, launcher, workspace, nodeRoot, run, sessionID, agentInfo,
                tppConfig, credentials);
            getCertificates(logger, launcher, workspace, nodeRoot, sessionID,
                agentInfo, certFile, chainFile);
            importCertificates(logger, launcher, workspace, nodeRoot, sessionID,
                agentInfo, certFile, chainFile, keystore, tempDir);
            invokeJarSignerVerify(logger, launcher, workspace, agentInfo,
                keystore, filesToVerify);
        } finally {
            logoutTpp(logger, launcher, workspace, nodeRoot, sessionID, agentInfo);
            Utils.deleteFileRecursiveOrPrintStackTrace(logger, tempDir);
        }
    }

    TppConfig getTppConfigByName(String name) {
        return PluginConfig.get().getTppConfigByName(name);
    }

    StandardUsernamePasswordCredentials findCredentials(TppConfig tppConfig) {
        return Utils.findCredentials(tppConfig.getCredentialsId());
    }

    private Collection<FilePath> getFilesToVerify(FilePath ws)
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
            false,
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

    private void getCertificates(Logger logger, Launcher launcher, FilePath ws,
        FilePath nodeRoot, String sessionID, AgentInfo agentInfo,
        FilePath certFile, FilePath chainFile)
        throws InterruptedException, IOException
    {
        FilePath pkcs11ConfigToolPath = getPkcs11ConfigToolPath(agentInfo, nodeRoot);

        Map<String, String> envs = new HashMap<String, String>();
        envs.put("LIBHSMINSTANCE", sessionID);

        invokeCommand(logger, launcher, ws,
            "Getting certificate chain from TPP.",
            "Successfully obtained certificate chain from TPP.",
            "Error obtaining certificate chain from TPP",
            "pkcs11config getcertificate",
            false,
            new String[]{
                pkcs11ConfigToolPath.getRemote(),
                "getcertificate",
                "--label=" + getCertLabel(),
                "--file=" + certFile.getRemote(),
                "--chainfile=" + chainFile.getRemote()
            },
            null,
            envs);
    }

    private void importCertificates(Logger logger, Launcher launcher, FilePath ws,
        FilePath nodeRoot, String sessionID, AgentInfo agentInfo,
        FilePath certFile, FilePath chainFile, FilePath keystore,
        FilePath tempDir)
        throws InterruptedException, IOException
    {
        invokeCommand(logger, launcher, ws,
            "Importing main certificate into temporary Java key store.",
            "Successfully imported main certificate into temporary Java key store.",
            "Error importing main certificate into temporary Java key store",
            "keytool -import",
            false,
            new String[]{
                "keytool",
                "-import",
                "-trustcacerts",
                "-file", certFile.getRemote(),
                "-alias", certFile.getRemote(),
                "-keystore", keystore.getRemote(),
                "--storepass", "notrelevant",
                "--noprompt"
            },
            null,
            null);

        List<String> chainParts = splitCertChain(chainFile.readToString());
        int i = 1;
        for (String chainPart: chainParts) {
            FilePath chainPartFile = tempDir.child("chain." + Integer.toString(i) + ".crt");
            chainPartFile.write(chainPart, "UTF-8");

            invokeCommand(logger, launcher, ws,
                String.format("Importing certificate chain [part %d] into temporary Java key store.", i),
                String.format("Successfully imported certificate chain [part %d] into temporary Java key store.", i),
                String.format("Error importing certificate chain [part %d] into temporary Java key store", i),
                "keytool -import",
                false,
                new String[]{
                    "keytool",
                    "-import",
                    "-trustcacerts",
                    "-file", chainPartFile.getRemote(),
                    "-alias", chainPartFile.getRemote(),
                    "-keystore", keystore.getRemote(),
                    "--storepass", "notrelevant",
                    "--noprompt"
                },
                null,
                null);

            i++;
        }
    }

    private List<String> splitCertChain(String chainCertData) {
        String[] lines = chainCertData.split("\r?\n");
        List<String> result = new ArrayList<String>();
        StringBuilder currentCert = new StringBuilder();

        for (String line: lines) {
            if (line.isEmpty()) {
                continue;
            }

            currentCert.append(line);
            currentCert.append("\n");

            if (line.indexOf("-END CERTIFICATE-") != -1) {
                result.add(currentCert.toString());
                currentCert = new StringBuilder();
            }
        }

        return result;
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
            false,
            new String[]{
                pkcs11ConfigToolPath.getRemote(),
                "revokegrant",
                "-force",
                "-clear",
            },
            null,
            envs);
    }

    private void invokeJarSignerVerify(Logger logger, Launcher launcher, FilePath ws,
        AgentInfo agentInfo, FilePath keystore, Collection<FilePath> filesToVerify)
        throws InterruptedException, IOException
    {
        for (FilePath fileToVerify: filesToVerify) {
            invokeCommand(logger, launcher, ws,
                "Verifying with jarsigner: " + fileToVerify.getRemote() + "",
                "Successfully verified '" + fileToVerify.getRemote() + "'.",
                "Error verifying '" + fileToVerify.getRemote() + "'",
                "jarsigner -verify",
                true,
                new String[]{
                    "jarsigner",
                    "-verify",
                    "-verbose",
                    "-keystore", keystore.getRemote(),
                    fileToVerify.getRemote(),
                },
                null,
                null);
        }
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

    private FilePath getPkcs11ConfigToolPath(AgentInfo agentInfo, FilePath nodeRoot) {
        return Utils.getPkcs11ConfigToolPath(agentInfo, nodeRoot,
            getVenafiCodeSigningInstallDir());
    }

    @Symbol("venafiVerifyWithJarSigner")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        @SuppressWarnings("rawtypes")
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return Messages.JarSignerVerifyBuilder_displayName();
        }

        public ListBoxModel doFillTppNameItems() {
            ListBoxModel items = new ListBoxModel();
            for (TppConfig config : PluginConfig.get().getTppConfigs()) {
                items.add(config.getName(), config.getName());
            }
            return items;
        }

        public FormValidation doCheckFile(@QueryParameter String value,
            @QueryParameter String glob)
        {
            if (glob.isEmpty()) {
                return FormValidation.validateRequired(value);
            } else if (!value.isEmpty()) {
                return FormValidation.error(Messages.JarSignerVerifyBuilder_fileAndGlobMutuallyExclusive());
            } else {
                return FormValidation.ok();
            }
        }

        public FormValidation doCheckGlob(@QueryParameter String value,
            @QueryParameter String file)
        {
            if (file.isEmpty()) {
                return FormValidation.validateRequired(value);
            } else if (!value.isEmpty()) {
                return FormValidation.error(Messages.JarSignerVerifyBuilder_fileAndGlobMutuallyExclusive());
            } else {
                return FormValidation.ok();
            }
        }
    }
}
