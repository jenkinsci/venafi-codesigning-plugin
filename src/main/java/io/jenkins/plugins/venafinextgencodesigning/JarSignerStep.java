package io.jenkins.plugins.venafinextgencodesigning;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

import org.jenkinsci.plugins.workflow.graph.FlowNode;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

public class JarSignerStep extends Step implements Serializable {
    private static final long serialVersionUID = 1;

    private String tppName;
    private String jarFile;
    private String certLabel;

    @DataBoundConstructor
    public JarSignerStep() {
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
    public StepExecution start(StepContext context) throws Exception {
        return new JarSignerStepExecution(this, context);
    }

    @Override
    public String toString() {
        return Messages.JarSignerStep_functionName();
    }

    @Extension
    public static final class DescriptorImpl extends StepDescriptor {
        private static final Set<Class<?>> REQUIRED_CONTEXTS = new HashSet<Class<?>>();

        static {
            REQUIRED_CONTEXTS.add(TaskListener.class);
            REQUIRED_CONTEXTS.add(FilePath.class);
            REQUIRED_CONTEXTS.add(Run.class);
            REQUIRED_CONTEXTS.add(FlowNode.class);
            REQUIRED_CONTEXTS.add(Launcher.class);
        };

        @Override
        public String getFunctionName() {
            return Messages.JarSignerStep_functionName();
        }

        @Override
        public String getDisplayName() {
            return Messages.JarSignerStep_displayName();
        }

        @Override
        public Set<Class<?>> getRequiredContext() {
            return REQUIRED_CONTEXTS;
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
