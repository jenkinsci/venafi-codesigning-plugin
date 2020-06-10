package io.jenkins.plugins.venaficodesigning;

import com.thoughtworks.xstream.annotations.XStreamAlias;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;

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
        public FormValidation doCheckArgument(@QueryParameter String value)
        {
            return FormValidation.validateRequired(value);
        }
    }
}
