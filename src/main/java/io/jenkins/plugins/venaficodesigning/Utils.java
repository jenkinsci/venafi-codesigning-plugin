package io.jenkins.plugins.venaficodesigning;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.annotation.Nullable;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;

import hudson.FilePath;
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

    public static void deleteFileOrPrintStackTrace(Logger logger, FilePath file) {
        try {
            if (file != null) {
                file.delete();
            }
        } catch (Exception e) {
            e.printStackTrace(logger.getOutput());
        }
    }

    public static void deleteWindowsRegistry(Logger logger, Launcher launcher, String path)
        throws IOException, InterruptedException
    {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Launcher.ProcStarter starter =
            launcher.
            launch().
            cmds(
                "reg",
                "delete",
                path,
                "/va",
                "/f"
            ).
            stdout(output).
            quiet(true);

        Proc proc = starter.start();
        int code = proc.join();

        if (code != 0) {
            String outputStr = output.toString("UTF-8").trim();
            if (outputStr.indexOf("The system was unable to find the specified registry key or value", 0) != -1) {
                throw new IOException("Error deleting Windows registry key '" + path
                    + "': the 'reg' command exited with code " + code
                    + " and the following output: " + outputStr);
            }
        }
    }

    public static FilePath detectVenafiCodeSigningInstallDir(AgentInfo agentInfo, FilePath nodeRoot,
        String userProvidedVenafiCodeSigningInstallDir)
    {
        if (userProvidedVenafiCodeSigningInstallDir != null) {
            return nodeRoot.child(userProvidedVenafiCodeSigningInstallDir);
        } else if (agentInfo.osType == OsType.MACOS) {
            return nodeRoot.child("/Library/Venafi/CodeSigning");
        } else if (agentInfo.osType == OsType.WINDOWS) {
            String programFiles = System.getenv("ProgramFiles");
            if (programFiles == null) {
                programFiles = "C:\\Program Files";
            }
            return nodeRoot.child(programFiles).child("Venafi");
        } else {
            return nodeRoot.child("/opt/venafi/codesign");
        }
    }

    public static FilePath getPkcs11DriverLibraryPath(AgentInfo agentInfo, FilePath nodeRoot,
        String userProvidedVenafiCodeSigningInstallDir)
    {
        FilePath toolsDir = detectVenafiCodeSigningInstallDir(agentInfo, nodeRoot,
            userProvidedVenafiCodeSigningInstallDir);
        if (agentInfo.osType == OsType.WINDOWS) {
            return toolsDir.child("PKCS11").child("VenafiPkcs11.dll");
        } else {
            return toolsDir.child("lib").child("venafipkcs11.so");
        }
    }

    public static void createPkcs11ProviderConfig(AgentInfo agentInfo, FilePath nodeRoot, FilePath file,
        String userProvidedVenafiCodeSigningInstallDir)
        throws IOException, InterruptedException
    {
        String libpath = getPkcs11DriverLibraryPath(agentInfo, nodeRoot,
            userProvidedVenafiCodeSigningInstallDir).getRemote();
        String contents = String.format(
            "name = VenafiPKCS11%n"
            + "library = \"%s\"%n"
            + "slot = 0%n",
            StringEscapeUtils.escapeJava(libpath)
        );
        file.write(contents, "UTF-8");
    }

    public static List<String> parseStringAsNewlineDelimitedList(String input) {
        List<String> result = new ArrayList<String>();
        for (String line: input.split("\\s+")) {
            line = line.trim();
            if (!line.isEmpty()) {
                result.add(line);
            }
        }
        return result;
    }
}
