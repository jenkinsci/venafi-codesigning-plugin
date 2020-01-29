package io.jenkins.plugins.venafinextgencodesigning;

import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

public class TpmEnv implements Serializable {

  static final long serialVersionUID = 42L;

  @Deprecated
  @SuppressWarnings("unused")
  private transient String id;

  private String envName;
  private String authUrl;
  private String hsmUrl;
  private String grantedUser;
  private Secret grantedToken;

  public TpmEnv() {
  }

  @DataBoundConstructor
  public TpmEnv(String envName, String authUrl, String hsmUrl, String grantedUser, Secret grantedToken) {
    this.envName = envName;
    this.authUrl = authUrl;
    this.hsmUrl = hsmUrl;
    this.grantedUser = grantedUser;
    this.grantedToken = grantedToken;
  }

  @SuppressWarnings({"unused", "deprecation"})
  @Deprecated
  public String getId() {
    return id;
  }

  public int getUniqueId() {
    int result = envName != null ? envName.hashCode() : 0;
    result = 31 * result + (authUrl != null ? authUrl.hashCode() : 0);
    result = 31 * result + (grantedUser != null ? grantedUser.hashCode() : 0);
    return result;
  }

  public String getEnvName() {
    return envName;
  }

  public String getAuthUrl() {
    return authUrl;
  }

  public String getHsmUrl() {
    return hsmUrl;
  }

  public String getGrantedUser() {
    return grantedUser;
  }

  public Secret getGrantedToken() {
    return grantedToken;
  }

}