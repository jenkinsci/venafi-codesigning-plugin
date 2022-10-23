package io.jenkins.plugins.venaficodesigning;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.net.MalformedURLException;
import java.net.URL;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("tpp-config")
public class TppConfig extends AbstractDescribableImpl<TppConfig> {
    private final String name;
    private final String authUrl;
    private final String hsmUrl;

    @DataBoundConstructor
    public TppConfig(String name, String authUrl, String hsmUrl) {
        this.name = name;
        this.authUrl = authUrl;
        this.hsmUrl = hsmUrl;
    }

    public String getName() {
        return name;
    }

    public String getAuthUrl() {
        return authUrl;
    }

    public String getHsmUrl() {
        return hsmUrl;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<TppConfig> {
        @Override
        public String getDisplayName() {
            return Messages.TppConfig_displayName();
        }

        public FormValidation doCheckName(@QueryParameter String value, @QueryParameter String id) {
            return FormValidation.validateRequired(value);
        }

        public FormValidation doCheckAuthUrl(@QueryParameter String value) {
            FormValidation result = FormValidation.validateRequired(value);
            if (result.kind != FormValidation.Kind.OK) {
                return result;
            }

            try {
                new URL(value);
            } catch (MalformedURLException e) {
                return FormValidation.error(
                    Messages.TppConfig_authUrlMalformed(),
                    e.getMessage());
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckHsmUrl(@QueryParameter String value) {
            FormValidation result = FormValidation.validateRequired(value);
            if (result.kind != FormValidation.Kind.OK) {
                return result;
            }

            try {
                new URL(value);
            } catch (MalformedURLException e) {
                return FormValidation.error(
                    Messages.TppConfig_hsmUrlMalformed(),
                    e.getMessage());
            }

            return FormValidation.ok();
        }

    }
}
