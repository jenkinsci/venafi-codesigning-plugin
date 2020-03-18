package io.jenkins.plugins.venafinextgencodesigning;

import java.util.Collections;

import javax.annotation.Nullable;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import org.apache.commons.lang.StringUtils;

import hudson.model.Item;
import hudson.security.ACL;

public class Utils {
    @Nullable
    public static StandardUsernamePasswordCredentials findCredentials(String credentialsId) {
        return findCredentials(credentialsId, null);
    }

    @Nullable
    public static StandardUsernamePasswordCredentials findCredentials(String credentialsId, Item item) {
        if (StringUtils.isBlank(credentialsId)) {
            return null;
        }
        return CredentialsMatchers.firstOrNull(
            CredentialsProvider.lookupCredentials(
                StandardUsernamePasswordCredentials.class,
                item,
                ACL.SYSTEM,
                Collections.emptyList()),
            CredentialsMatchers.allOf(
                CredentialsMatchers.withId(credentialsId),
                CredentialsMatchers.anyOf(
                    CredentialsMatchers.instanceOf(StandardUsernamePasswordCredentials.class))));
    }
}
