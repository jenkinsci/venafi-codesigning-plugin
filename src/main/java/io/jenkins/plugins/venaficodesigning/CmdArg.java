package io.jenkins.plugins.venaficodesigning;

import com.thoughtworks.xstream.annotations.XStreamAlias;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

@XStreamAlias("cmd-arg")
public class CmdArg extends AbstractDescribableImpl<CmdArg> {
    private String argument;

    @DataBoundConstructor
    public CmdArg() {
    }

    public String getArgument() {
        return argument;
    }

    @DataBoundSetter
    public void setArgument(String value) {
        this.argument = value;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<CmdArg> {
    }
}
