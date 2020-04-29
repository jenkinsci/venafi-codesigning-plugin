package io.jenkins.plugins.venaficodesigning;

import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;

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
    }

    @Test
    public void testNoFileOrGlobGiven() throws Exception {
        JarSignerBuilder builder = spy(new JarSignerBuilder());
        builder.setTppName(TPP_NAME);
        builder.setCertLabel("label");
        doReturn(tppConfig).when(builder).getTppConfigByName(TPP_NAME);
        doReturn(credentials).when(builder).findCredentials(Mockito.any());

        FreeStyleProject project = jenkins.createFreeStyleProject();
        project.getBuildersList().add(builder);

        Future<FreeStyleBuild> run = project.scheduleBuild2(0);
        FreeStyleBuild build = jenkins.assertBuildStatus(Result.FAILURE, run);
        jenkins.assertLogContains("Either the 'file' or the 'glob' parameter must be specified.", build);
    }

    @Test
    public void testBothFileAndGlobGiven() throws Exception {
        JarSignerBuilder builder = spy(new JarSignerBuilder());
        builder.setTppName(TPP_NAME);
        builder.setFile("file");
        builder.setGlob("file");
        builder.setCertLabel("label");
        doReturn(tppConfig).when(builder).getTppConfigByName(TPP_NAME);
        doReturn(credentials).when(builder).findCredentials(Mockito.any());

        FreeStyleProject project = jenkins.createFreeStyleProject();
        project.getBuildersList().add(builder);

        Future<FreeStyleBuild> run = project.scheduleBuild2(0);
        FreeStyleBuild build = jenkins.assertBuildStatus(Result.FAILURE, run);
        jenkins.assertLogContains("Either the 'file' or the 'glob' parameter must be specified,"
            + " but not both at the same time.", build);
    }
}
