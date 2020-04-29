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
import hudson.tasks.BuildStepDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import jenkins.tasks.SimpleBuildStep;

import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class JarSignerVerifyBuilder extends Builder implements SimpleBuildStep {
    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String file;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String glob;

    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    private String venafiCodeSigningInstallDir;

    @DataBoundConstructor
    public JarSignerVerifyBuilder() {
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

        AgentInfo agentInfo = nodeRoot.act(new AgentInfo.GetAgentInfo());
        logger.log("Detected OS: %s", agentInfo.osType);

        checkFileOrGlobSpecified();

        FilePath pkcs11ProviderConfigFile = null;
        try {
            Collection<FilePath> filesToVerify = getFilesToVerify(workspace);
            pkcs11ProviderConfigFile = workspace.createTempFile("pkcs11-provider", ".conf");

            Utils.createPkcs11ProviderConfig(agentInfo, nodeRoot, pkcs11ProviderConfigFile,
                getVenafiCodeSigningInstallDir());
            invokeJarSignerVerify(logger, launcher, workspace, agentInfo,
                pkcs11ProviderConfigFile, filesToVerify);
        } finally {
            Utils.deleteFileOrPrintStackTrace(logger, pkcs11ProviderConfigFile);
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

    private void invokeJarSignerVerify(Logger logger, Launcher launcher, FilePath ws,
        AgentInfo agentInfo, FilePath pkcs11ProviderConfigFile, Collection<FilePath> filesToVerify)
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
                    "-keystore", "NONE",
                    "-storetype", "PKCS11",
                    "-storepass", "bogus",
                    "-providerclass", "sun.security.pkcs11.SunPKCS11",
                    "-providerArg", pkcs11ProviderConfigFile.getRemote(),
                    "-certs",
                    fileToVerify.getRemote(),
                },
                null);
        }
    }

    private String invokeCommand(Logger logger, Launcher launcher, FilePath ws,
        String preMessage, String successMessage, String errorMessage,
        String shortCommandLine,  boolean printOutputOnSuccess, String[] cmdArgs,
        boolean[] masks)
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
    }
}
