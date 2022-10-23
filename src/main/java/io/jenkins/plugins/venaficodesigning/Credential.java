package io.jenkins.plugins.venaficodesigning;

import com.cloudbees.plugins.credentials.common.StandardUsernameListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Project;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.List;

import static com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials;

public class Credential extends AbstractDescribableImpl<Credential> {

    private final String credentialsId;

    @DataBoundConstructor
    public Credential(String credentialsId) {
        this.credentialsId = credentialsId;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    public static StandardUsernamePasswordCredentials lookupSystemCredentials(String credentialsId) {
        return Utils.lookupSystemCredentials(credentialsId);
    }

    @Extension
    public static final class CredentialDescriptor extends Descriptor<Credential> {
        @Override
        public String getDisplayName() {
            return "Credential";
        }

        public ListBoxModel doFillCredentialsIdItems(@AncestorInPath Project context) {
            List<StandardUsernamePasswordCredentials> creds = lookupCredentials(
                StandardUsernamePasswordCredentials.class, context, ACL.SYSTEM, PluginConfig.HTTP_SCHEME,
                PluginConfig.HTTPS_SCHEME);

            return new StandardUsernameListBoxModel().withAll(creds);
        }

    }

}
