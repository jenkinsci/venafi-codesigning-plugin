package io.jenkins.plugins.venafinextgencodesigning;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Proc;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Result;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Publisher;
import hudson.tasks.Recorder;
import hudson.util.ArgumentListBuilder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

public class CodeSigningPostAction extends Recorder {

  private List<CodeSign> entries = Collections.emptyList();

  @DataBoundConstructor
  @SuppressWarnings("unused")
  public CodeSigningPostAction(List<CodeSign> codeSign ) {
    this.entries = codeSign ;
    if (this.entries == null) {
      this.entries = Collections.emptyList();
    }
  }

  @Override
  public BuildStepMonitor getRequiredMonitorService() {
    return BuildStepMonitor.NONE;
  }

  private boolean isPerformDeployment(AbstractBuild build) {
    Result result = build.getResult();
    return result == null || result.isBetterOrEqualTo(Result.UNSTABLE);

  }

  @SuppressWarnings("unused")
  public List<CodeSign> getEntries() {
    return entries;
  }

  @Override
  public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws InterruptedException, IOException {
    if (isPerformDeployment(build)) {
      listener.getLogger().println("[VenafiTPM] - Starting code signing ...");
      listener.getLogger().println("[VenafiTPM] - Finished code signing ...");
    } else {
      listener.getLogger().println("[VenafiTPM] - Skipping code signing ...");
    }
    return true;
  }

  @Extension
  @SuppressWarnings("unused")
  public static final class TpmEnvsDescriptor extends BuildStepDescriptor<Publisher> {

    public static final String DISPLAY_NAME = Messages.job_displayName();

    @Override
    public boolean isApplicable(Class<? extends AbstractProject> jobType) {
      return true;
    }

    private volatile List<TpmEnv> tpmEnvs = new ArrayList<>();

    public TpmEnvsDescriptor() {
      load();
    }

    @Override
    public String getDisplayName() {
      return DISPLAY_NAME;
    }

    public List<TpmEnv> getTpmEnvs() {
      return tpmEnvs;
    }

    public ListBoxModel doFillTargetEnvItems() {
      ListBoxModel items = new ListBoxModel();
      for (TpmEnv tpmEnv : tpmEnvs) {
        items.add(tpmEnv.getEnvName(), tpmEnv.getEnvName());
      }
      return items;
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
      tpmEnvs = req.bindJSONToList(TpmEnv.class, json.get("tpmEnv"));
      save();
      return true;
    }

    public FormValidation doCheckEnvName(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException {
      return FormValidation.validateRequired(value);
    }

    public FormValidation doCheckAuthUrl(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException {
      return FormValidation.validateRequired(value);
    }

    public FormValidation doCheckHsmUrl(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException {
      return FormValidation.validateRequired(value);
    }

    public FormValidation doCheckGrantedUser(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException {
      return FormValidation.validateRequired(value);
    }

    public FormValidation doCheckGrantedToken(@AncestorInPath AbstractProject project, @QueryParameter String value) throws IOException, InterruptedException {
      FilePath workspace = project.getSomeWorkspace();
      if (workspace != null) {
        String msg = workspace.validateAntFileMask(value);
        if (msg != null) {
          return FormValidation.error(msg);
        }
        return FormValidation.ok();
      } else {
        return FormValidation.warning(Messages.noworkspace());
      }
    }

  }
}