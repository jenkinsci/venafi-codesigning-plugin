package io.jenkins.plugins.venaficodesigning;

import com.thoughtworks.xstream.annotations.XStreamAlias;

import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

@XStreamAlias("cmd-arg")
public class CmdArg extends AbstractDescribableImpl<CmdArg> {
    private final String argument;

    @DataBoundConstructor
    public CmdArg(String argument) {
        this.argument = argument;
    }

    public String getArgument() {
        return argument;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<CmdArg> {
    }
}
