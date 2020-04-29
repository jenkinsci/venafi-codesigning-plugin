package io.jenkins.plugins.venaficodesigning;

public enum OsType {
    MACOS("macOS"),
    GENERIC_UNIX("Unix (generic)"),
    WINDOWS("Windows");

    private String displayName;

    private OsType(String displayName) {
        this.displayName = displayName;
    }

    public boolean isUnixCompatible() {
        return this == MACOS || this == GENERIC_UNIX;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
