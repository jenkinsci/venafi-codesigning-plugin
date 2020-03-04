package io.jenkins.plugins.venafinextgencodesigning;

import java.io.IOException;

import hudson.Launcher;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.tasks.BuildStepDescriptor;
import jenkins.tasks.SimpleBuildStep;

import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

public class JarSignerBuilder extends Builder implements SimpleBuildStep {
    private String tpmServerConfigName;
    private String jarFile;
    private String certLabel;
    private String certChainFile;

    @DataBoundConstructor
    public JarSignerBuilder() {
    }

    public String getTpmServerConfigName() {
        return tpmServerConfigName;
    }

    @DataBoundSetter
    public void setTpmServerConfigName(String value) {
        this.tpmServerConfigName = value;
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
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener) throws InterruptedException, IOException {
        System.err.println("!!!!! Action run!");
        listener.getLogger().println("Hello, world! server config count = " + PluginConfig.get().getTpmServerConfigs().size());
    }

    @Symbol("venafiCodeSignWithJarSigner")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return Messages.JarSignerBuilder_displayName();
        }

        public ListBoxModel doFillTpmServerConfigNameItems() {
            ListBoxModel items = new ListBoxModel();
            for (TpmServerConfig config: PluginConfig.get().getTpmServerConfigs()) {
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
