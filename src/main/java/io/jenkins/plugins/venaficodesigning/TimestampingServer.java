package io.jenkins.plugins.venaficodesigning;

import com.thoughtworks.xstream.annotations.XStreamAlias;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;

@XStreamAlias("timestamping-server")
public class TimestampingServer extends AbstractDescribableImpl<TimestampingServer> {
    private final String address;

    @DataBoundConstructor
    public TimestampingServer(String address) {
        this.address = address;
    }

    public String getAddress() {
        return address;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<TimestampingServer> {
        public FormValidation doCheckAddress(@QueryParameter String value)
        {
            return FormValidation.validateRequired(value);
        }
    }
}
