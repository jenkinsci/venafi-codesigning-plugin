package io.jenkins.plugins.venafinextgencodesigning;

import hudson.Extension;
import hudson.util.Secret;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.kohsuke.stapler.DataBoundConstructor;

public class CodeSign extends AbstractDescribableImpl<CodeSign> {

  private final String targetEnv;
  private final String intTool;
  private final String certChain;
  private final String certLabel;
  private final Secret storePass;

  @DataBoundConstructor
  public CodeSign(String targetEnv, String intTool, String certChain, String certLabel, Secret storePass) {
    this.targetEnv = targetEnv;
    this.intTool = intTool;
    this.certChain = certChain;
    this.certLabel = certLabel;
    this.storePass = storePass;
  }

  public String getTargetEnv() {
    return targetEnv;
  }

  public String getIntTool() {
    return intTool;
  }

  public String getCertChain() {
    return certChain;
  }

  public String getCertLabel() {
    return certLabel;
  }

  public Secret getStorePass() {
    return storePass;
  }

  @Extension
  public static class DescriptorImpl extends Descriptor<CodeSign> {

    @Override
    public String getDisplayName() {
      return ""; // unused
    }
  }
}