package io.jenkins.plugins.venaficodesigning;

import java.io.IOException;
import java.util.ArrayList;

public class WindowsRegistry {
    private CommandLauncher launcher;
    private boolean use64Bit;

    public WindowsRegistry(CommandLauncher launcher, boolean use64Bit) {
        this.launcher = launcher;
        this.use64Bit = use64Bit;
    }

    public String readKey(String keyName, String valueName)
        throws IOException, InterruptedException
    {
        ArrayList<String> cmdArgs = new ArrayList<String>();
        cmdArgs.add("reg");
        cmdArgs.add("query");
        cmdArgs.add(keyName);
        cmdArgs.add("/v");
        cmdArgs.add(valueName);
        if (use64Bit) {
            cmdArgs.add("/reg:64");
        } else {
            cmdArgs.add("/reg:32");
        }

        launcher.
            cmds(cmdArgs.toArray(new String[0])).
            quiet(true).
            startAndJoin();

        int code = launcher.getCode();
        String output = launcher.getOutput().trim();

        if (code == 1 && output.indexOf("The system was unable to find the specified registry key or value") != -1) {
            return null;
        } else if (code != 0) {
            throw new IOException("Error reading Windows registry key '" + keyName
                + "\\" + valueName + "': the 'reg' command exited with code " + code
                + " and the following output: " + output);
        }

        String[] lines = output.split("\r?\n");
        for (String line: lines) {
            int idx = line.indexOf("REG_SZ");
            if (idx != -1) {
                return line.substring(idx + "REG_SZ".length()).trim();
            }
        }

        throw new IOException("Error reading Windows registry key '" + keyName
            + "\\" + valueName + "': unable to parse 'reg' command output: "
            + output);
    }
}
