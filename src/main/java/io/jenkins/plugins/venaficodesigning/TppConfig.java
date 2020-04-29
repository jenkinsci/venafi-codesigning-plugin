package io.jenkins.plugins.venaficodesigning;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;

import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("tpp-config")
public class TppConfig extends AbstractDescribableImpl<TppConfig> {
    private String name;
    private String authUrl;
    private String hsmUrl;
    private final String credentialsId;

    @DataBoundConstructor
    public TppConfig(String credentialsId) {
        this.credentialsId = credentialsId;
    }

    public String getName() {
        return name;
    }

    @DataBoundSetter
    public void setName(String value) {
        this.name = value;
    }

    public String getAuthUrl() {
        return authUrl;
    }

    @DataBoundSetter
    public void setAuthUrl(String value) {
        this.authUrl = value;
    }

    public String getHsmUrl() {
        return hsmUrl;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    @DataBoundSetter
    public void setHsmUrl(String value) {
        this.hsmUrl = value;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<TppConfig> {
        @Override
        public String getDisplayName() {
            return Messages.TppConfig_displayName();
        }

        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String credentialsId) {
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                    && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                .includeMatchingAs(ACL.SYSTEM,
                    item,
                    StandardCredentials.class,
                    new ArrayList<>(),
                    CredentialsMatchers.anyOf(
					    CredentialsMatchers.instanceOf(StandardUsernamePasswordCredentials.class),
					    CredentialsMatchers.instanceOf(UsernamePasswordCredentials.class))
                )
                .includeCurrentValue(credentialsId);
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

        public FormValidation doCheckCredentialsId(@AncestorInPath Item item, @QueryParameter String credentialsId) {
            if (item == null) {
                    if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                        return FormValidation.ok();
                    }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                    && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return FormValidation.ok();
                }
            }

            if (Utils.findCredentials(credentialsId, item) == null) {
                return FormValidation.error("Cannot find currently selected credentials");
            }

            return FormValidation.ok();
        }
    }
}
