package io.jenkins.plugins.venaficodesigning;

import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

import java.util.concurrent.Future;

import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;

public class JarSignerBuilderTest {
    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    private static final String TPP_NAME = "default";

    private TppConfig tppConfig;
    private StandardUsernamePasswordCredentials credentials;

	@Before
	public void createMocks() {
        tppConfig = mock(TppConfig.class);
        when(tppConfig.getName()).thenReturn(TPP_NAME);
        when(tppConfig.getAuthUrl()).thenReturn("http://auth");
        when(tppConfig.getHsmUrl()).thenReturn("http://hsm");
        when(tppConfig.getCredentialsId()).thenReturn("credentials-id");

        credentials = mock(StandardUsernamePasswordCredentials.class);
        doReturn("username").when(credentials).getUsername();
        doReturn(null).when(credentials).getPassword();
    }

    @Test
    public void testSignFile() throws Exception {
        JarSignerBuilder builder = spy(new JarSignerBuilder(TPP_NAME, "label"));
        builder.setFile("file.jar");
        doReturn(tppConfig).when(builder).getTppConfigByName(TPP_NAME);
        doReturn(credentials).when(builder).findCredentials(Mockito.any());
        doReturn(0).when(builder).startAndJoinProc(Mockito.any());

        FreeStyleProject project = jenkins.createFreeStyleProject();
        project.getBuildersList().add(builder);

        Future<FreeStyleBuild> run = project.scheduleBuild2(0);
        FreeStyleBuild build = jenkins.assertBuildStatusSuccess(run);
        jenkins.assertLogContains("Logging into TPP: configuring client: requesting grant from server", build);
        jenkins.assertLogContains("Successfully obtained grant from TPP", build);
        jenkins.assertLogContains("Signing with jarsigner", build);
        jenkins.assertLogContains("Successfully signed", build);
        jenkins.assertLogContains("Logging out of TPP", build);
        jenkins.assertLogContains("Successfully revoked server grant", build);
    }
}
