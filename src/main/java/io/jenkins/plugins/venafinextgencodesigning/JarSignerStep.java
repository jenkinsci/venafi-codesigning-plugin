package io.jenkins.plugins.venafinextgencodesigning;

import java.io.PrintStream;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

import org.jenkinsci.plugins.workflow.FilePathUtils;
import org.jenkinsci.plugins.workflow.steps.AbstractStepExecutionImpl;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

public class JarSignerStep extends Step implements Serializable {
    private static final long serialVersionUID = 1;

    private String tpmServerName;
    private String jarFile;
    private String certLabel;
    private String certChainFile;

    @DataBoundConstructor
    public JarSignerStep() {
    }

    public String getTpmServerName() {
        return tpmServerName;
    }

    @DataBoundSetter
    public void setTpmServerName(String value) {
        this.tpmServerName = value;
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

    public String getCertChainFile() {
        return certChainFile;
    }

    @DataBoundSetter
    public void setCertChainFile(String value) {
        this.certChainFile = value;
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        return new Execution(context);
    }

    public class Execution extends AbstractStepExecutionImpl {
        private static final long serialVersionUID = 1;

        public Execution(StepContext context) {
            super(context);
        }

        @Override
        public boolean start() throws Exception {
            PrintStream logger = getContext().get(TaskListener.class).getLogger();
            FilePath ws = getContext().get(FilePath.class);
            //Launcher launcher = context.get(Launcher.class);
            logger.println("Hello, world! server config count = " + PluginConfig.get().getTpmServerConfigs().size());
            logger.println("Current workspace = " + ws);
            logger.println("Node name = " + FilePathUtils.getNodeName(ws));
            getContext().onSuccess(null);
            return true;
        }
    }

    @Extension
    public static final class DescriptorImpl extends StepDescriptor {
        private static final Set<Class<?>> REQUIRED_CONTEXTS = new HashSet<Class<?>>();

        static {
            REQUIRED_CONTEXTS.add(TaskListener.class);
            REQUIRED_CONTEXTS.add(Launcher.class);
        };

        @Override
        public String getFunctionName() {
            return "venafiCodeSignWithJarSigner";
        }

        @Override
        public String getDisplayName() {
            return Messages.JarSignerBuilder_displayName();
        }

        @Override
        public Set<Class<?>> getRequiredContext() {
            return REQUIRED_CONTEXTS;
        }

        public ListBoxModel doFillTpmServerNameItems() {
            ListBoxModel items = new ListBoxModel();
            for (TpmServerConfig config : PluginConfig.get().getTpmServerConfigs()) {
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

        public FormValidation doCheckCertChainFile(@QueryParameter String value) {
            return FormValidation.validateRequired(value);
        }
    }
}
