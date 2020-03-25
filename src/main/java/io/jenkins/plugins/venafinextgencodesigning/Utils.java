package io.jenkins.plugins.venafinextgencodesigning;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;

import javax.annotation.Nullable;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import org.apache.commons.lang.StringUtils;

import hudson.Launcher;
import hudson.Proc;
import hudson.model.Computer;
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

    // Determines the FQDN of the given Computer.
    //
    // Computer.getHostName() (which does return an FQDN) isn't good enough and
    // sometimes fails to detect the hostname. So we fallback to invoking the
    // `hostname -f` command, but only on a Unix-compatible system.
    //
    // Never returns null. If the hostname cannot be determined, then returns
    // the empty string.
    public static String getFqdn(Computer computer, Launcher launcher, AgentInfo agentInfo)
        throws IOException, InterruptedException
    {
        String result = computer.getHostName();
        if (result != null) {
            return result;
        }

        if (!agentInfo.osType.isUnixCompatible()) {
            return "";
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Launcher.ProcStarter starter =
            launcher.
            launch().
            cmds("hostname", "-f").
            stdout(output).
            quiet(true);

        Proc proc = starter.start();
        int code = proc.join();

        if (code == 0) {
            return output.toString("UTF-8").trim();
        } else {
            throw new IOException("Error determining node's FQDN: command 'hostname -f' exited with code " + code);
        }
    }
}
