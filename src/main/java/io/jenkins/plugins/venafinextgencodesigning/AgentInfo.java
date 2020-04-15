package io.jenkins.plugins.venafinextgencodesigning;

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
    public boolean isWindows64Bit;

    public static final class GetAgentInfo implements FileCallable<AgentInfo> {
        private static final long serialVersionUID = 1;

        @Override
        public AgentInfo invoke(File nodeRoot, VirtualChannel virtualChannel)
            throws IOException, InterruptedException
        {
            AgentInfo info = new AgentInfo();
            info.username = System.getProperty("user.name");
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
