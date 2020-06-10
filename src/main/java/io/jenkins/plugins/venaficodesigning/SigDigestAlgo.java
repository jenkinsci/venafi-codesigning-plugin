package io.jenkins.plugins.venaficodesigning;

import com.thoughtworks.xstream.annotations.XStreamAlias;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;

@XStreamAlias("sig-digest-algo")
public class SigDigestAlgo extends AbstractDescribableImpl<SigDigestAlgo> {
    private String algorithm;

    @DataBoundConstructor
    public SigDigestAlgo(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SigDigestAlgo> {
        public FormValidation doCheckAlgorithm(@QueryParameter String value)
        {
            return FormValidation.validateRequired(value);
        }
    }
}
