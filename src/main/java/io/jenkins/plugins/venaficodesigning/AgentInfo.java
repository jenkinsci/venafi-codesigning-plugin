package io.jenkins.plugins.venaficodesigning;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;

import org.jenkinsci.remoting.RoleChecker;

import hudson.Platform;
import hudson.FilePath.FileCallable;
import hudson.remoting.VirtualChannel;

public final class AgentInfo implements Serializable {
    private static final long serialVersionUID = 1;

    public String username;
    public OsType osType;
    public boolean isJre64Bit;
    public boolean isWindows64Bit;

    @Override
    public String toString() {
        String result = String.format("OS=%s, JRE=%s",
            osType, isJre64Bit ? "64-bit" : "32-bit");
        if (osType == OsType.WINDOWS) {
            result += ", Windows=" + (isWindows64Bit ? "64-bit" : "32-bit");
        }
        return result;
    }

    public static final class GetAgentInfo implements FileCallable<AgentInfo> {
        private static final long serialVersionUID = 1;

        @Override
        public AgentInfo invoke(File nodeRoot, VirtualChannel virtualChannel)
            throws IOException, InterruptedException
        {
            AgentInfo info = new AgentInfo();
            info.username = System.getProperty("user.name");
            info.isJre64Bit = !System.getProperty("os.arch").equals("x86");
            if (Platform.isDarwin()) {
                info.osType = OsType.MACOS;
            } else if (Platform.current() == Platform.WINDOWS) {
                info.osType = OsType.WINDOWS;
                info.isWindows64Bit = (System.getenv("ProgramFiles(x86)") != null);
            } else {
                info.osType = OsType.GENERIC_UNIX;
            }
            return info;
        }

        @Override
        public void checkRoles(RoleChecker roleChecker) throws SecurityException {
            // Do nothing
        }
    }
}
