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

    public static void deleteFileRecursiveOrPrintStackTrace(Logger logger, FilePath file) {
        try {
            if (file != null) {
                file.deleteRecursive();
            }
        } catch (Exception e) {
            e.printStackTrace(logger.getOutput());
        }
    }

    public static void deleteWindowsRegistry(Logger logger, Launcher launcher,
        boolean use64Bit, String path)
        throws IOException, InterruptedException
    {
        ArrayList<String> cmdArgs = new ArrayList<String>();
        cmdArgs.add("reg");
        cmdArgs.add("delete");
        cmdArgs.add(path);
        cmdArgs.add("/va");
        cmdArgs.add("/f");
        if (use64Bit) {
            cmdArgs.add("/reg:64");
        } else {
            cmdArgs.add("/reg:32");
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Launcher.ProcStarter starter =
            launcher.
            launch().
            cmds(cmdArgs.toArray(new String[0])).
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
            // The Venafi PKCS11 driver is loaded by jarsigner.exe,
            // so the driver's architecture must match jarsigner's architecture.
            return toolsDir.child("PKCS11").child(agentInfo.isJre64Bit
                ? "VenafiPKCS11.dll"
                : "VenafiPKCS11-x86.dll");
        } else {
            return toolsDir.child("lib").child("venafipkcs11.so");
        }
    }

    static public FilePath getPkcs11ConfigToolPath(AgentInfo agentInfo, FilePath nodeRoot,
        String venafiCodeSigningInstallDir)
    {
        FilePath toolsDir = Utils.detectVenafiCodeSigningInstallDir(agentInfo, nodeRoot,
            venafiCodeSigningInstallDir);
        if (agentInfo.osType == OsType.WINDOWS) {
            // The Venafi PKCS11 driver stores credentials in the Windows registry.
            // 32-bit and 64-bit executables have access to different Windows registry hives,
            // so we need to make sure that the architecture of pkcs11config.exe matches that
            // of jarsigner.exe.
            String exe = agentInfo.isJre64Bit ? "PKCS11Config.exe" : "PKCS11Config-x86.exe";
            return toolsDir.child("PKCS11").child(exe);
        } else {
            return toolsDir.child("bin").child("pkcs11config");
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
