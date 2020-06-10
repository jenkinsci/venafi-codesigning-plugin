package io.jenkins.plugins.venaficodesigning;

import com.thoughtworks.xstream.annotations.XStreamAlias;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;

@XStreamAlias("timestamping-server")
public class TimestampingServer extends AbstractDescribableImpl<TimestampingServer> {
    private String address;

    @DataBoundConstructor
    public TimestampingServer() {
    }

    public String getAddress() {
        return address;
    }

    @DataBoundSetter
    public void setAddress(String value) {
        this.address = value;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<TimestampingServer> {
    }
}
