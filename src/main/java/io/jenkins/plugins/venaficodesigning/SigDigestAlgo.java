package io.jenkins.plugins.venaficodesigning;

import com.thoughtworks.xstream.annotations.XStreamAlias;

import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

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
    }
}
