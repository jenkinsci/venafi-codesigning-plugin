package io.jenkins.plugins.venaficodesigning;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.cloudbees.plugins.credentials.domains.SchemeRequirement;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

import hudson.Extension;
import hudson.XmlFile;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

@Extension
public class PluginConfig extends GlobalConfiguration {

    public static final SchemeRequirement HTTP_SCHEME = new SchemeRequirement("http");
   	public static final SchemeRequirement HTTPS_SCHEME = new SchemeRequirement("https");

    public static final String CONFIGURATION_ID = "venafi-code-signing-plugin-configuration";
    public static final PluginConfig EMPTY_CONFIG = new PluginConfig(Collections.emptyList());

    private List<TppConfig> tppConfigs = new ArrayList<>();

    @Nonnull
    public static PluginConfig get() {
        PluginConfig result = PluginConfig.all().get(PluginConfig.class);
        if (result == null) {
            return PluginConfig.EMPTY_CONFIG;
        } else {
            return result;
        }
    }

    public PluginConfig() {
        load();
    }

    public PluginConfig(List<TppConfig> tppConfigs) {
        this.tppConfigs = tppConfigs;
    }

    @Nonnull
    public List<TppConfig> getTppConfigs() {
        return tppConfigs;
    }

    @Nullable
    public TppConfig getTppConfigByName(String name) {
        for (TppConfig config: tppConfigs) {
            if (config.getName().equals(name)) {
                return config;
            }
        }
        return null;
    }

    @DataBoundSetter
    public void setTppConfigs(List<TppConfig> value) {
        this.tppConfigs = value;
    }

    @Override
    public String getId() {
        return CONFIGURATION_ID;
    }

    @Override
    protected XmlFile getConfigFile() {
        return new XmlFile(Jenkins.XSTREAM2, super.getConfigFile().getFile());
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        try {
            req.bindJSON(this, json);
        } catch (Exception e) {
            throw new FormException(
                String.format(Messages.PluginConfig_malformedError(), e.getMessage()),
                e, CONFIGURATION_ID);
        }

        String duplicateName = findDuplicateTppConfigName(tppConfigs);
        if (duplicateName != null) {
            throw new FormException(
                String.format(Messages.PluginConfig_duplicateTppConfigName(), duplicateName),
                CONFIGURATION_ID);
        }

        save();
        return true;
    }

    @Override
    public String getDisplayName() {
        return Messages.PluginConfig_displayName();
    }

    private String findDuplicateTppConfigName(List<TppConfig> tppConfigs) {
        Set<String> namesSeen = new HashSet<>();
        for (TppConfig config: tppConfigs) {
            if (!namesSeen.add(config.getName())) {
                return config.getName();
            }
        }
        return null;
    }
}
