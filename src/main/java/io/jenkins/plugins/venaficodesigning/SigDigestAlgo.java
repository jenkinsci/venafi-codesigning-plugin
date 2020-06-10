package io.jenkins.plugins.venaficodesigning;

import com.thoughtworks.xstream.annotations.XStreamAlias;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

@XStreamAlias("sig-digest-algo")
public class SigDigestAlgo extends AbstractDescribableImpl<SigDigestAlgo> {
    private String algorithm;

    @DataBoundConstructor
    public SigDigestAlgo() {
    }

    public String getAlgorithm() {
        return algorithm;
    }

    @DataBoundSetter
    public void setAlgorithm(String value) {
        this.algorithm = value;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SigDigestAlgo> {
    }
}
