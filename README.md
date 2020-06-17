# Venafi CodeSign Protect plugin for Jenkins

This plugin integrates [Venafi CodeSign Protect](https://www.venafi.com/platform/code-signing) with Jenkins-based CI/CD processes.

Venafi CodeSign Protect is a solution for securing machines against attacks and exploits, by signing executables, libraries and other machine runtime artifacts with digital signatures. Unlike naive methods of code signing, Venafi CodeSign Protect is more secure, by storing and securing the signing key separately from the CI/CD infrastructure (perhaps even in a Hardware Security Module) and by providing access control to signing keys. It also provides important insights to security teams, such as how and when signing keys are used.

This plugin allows one to sign and verify files through Venafi CodeSign Protect. The following signing tools are supported:

 * Jarsigner (Java)
 * Signtool (Windows)

**Table of contents**

 - [Setup & usage overview](#setup-usage-overview)
 - [Compatibility](#compatibility)
 - [Client tools installation caveats](#client-tools-installation-caveats)
 - [TPP configuration](#tpp-configuration)
 - [Security & master-slave node setup](#security-master-slave-node-setup)
 - [Build steps & pipeline functions](#build-steps-pipeline-functions)
    - [Sign with Jarsigner (`venafiCodeSignWithJarSigner`)](#sign-with-jarsigner-venaficodesignwithjarsigner)
    - [Verify with Jarsigner (`venafiVerifyWithJarSigner`)](#verify-with-jarsigner-venafiverifywithjarsigner)
    - [Sign with Signtool (`venafiCodeSignWithSignTool`)](#sign-with-signtool-venaficodesignwithsigntool)
    - [Verify with Signtool (`venafiVerifyWithSignTool`)](#verify-with-signtool-venafiverifywithsigntool)

## Setup & usage overview

You must already have access to one or more Venafi Trust Protection Platforms™ (TPPs). This plugin requires you to [configure TPP address and authentication details](#tpp-configuration).

This plugin works by shelling out to the Venafi CodeSign Protect client tools, on the node(s) on which Jenkins jobs execute. Therefore, you must already have the CodeSign Protect client tools installed on these nodes. The plugin will not install them for you.

Note that there are some caveats w.r.t. [client tools installation](#client-tools-installation-caveats) and [security](#security-master-slave-node-setup) to be aware of.

You do *not* need to *configure* the client tools (i.e. they don't need to be configured with a TPP address or credentials). They just need to be installed. This plugin will take care of configuring the client tools with specific TPPs.

Once the aforementioned are set up, go to [TPP configuration](#tpp-configuration). You are then ready to proceed with main usage: see [Build steps & pipeline functions](#build-steps-pipeline-functions).

## Compatibility

This plugin is compatible with:

 * Trust Protection Platform 20.2 or later.
 * Venafi CodeSign Protect client tools 20.2 or later.

## Client tools installation caveats

The Venafi CodeSign Protect client tools manual for Java, may instruct you to register its PKCS11 security provider inside `java.security`. **Do not do this**, because it may prevent Jenkins, or a Jenkins slave agent, from starting.

If you see an error like this, then it's a sign that you need to unregister the Venafi CodeSign Protect client tools PKCS11 security provider from `java.security`:

~~~
Loaded: "/opt/venafi/codesign/lib/venafipkcs11.so"

...

3: C_Initialize
2020-03-18 19:56:02.940
[in] pInitArgs = (nil)
Returned:  5 CKR_GENERAL_ERROR
~~~

## TPP configuration

This plugin requires that you define which TPPs are available and how to connect to them.

Inside Jenkins, go to Manage Jenkins ➜ Configure System. Scroll down to "Venafi Code Signing" and define your TPPs there.

## Security & master-slave node setup

We strongly recommend that you execute your Jenkins jobs inside Jenkins slave nodes, not on the Jenkins master node.

When you execute jobs on the Jenkins master node, it's possible for malicious jobs to access Jenkins' secrets by reading Jenkins' configuration files. This means that malicious jobs are, for example, able to steal TPP credentials.

See also:

 * [Securing Jenkins](https://www.jenkins.io/doc/book/system-administration/security/)
 * [Slave to Master Access Control](https://wiki.jenkins.io/display/JENKINS/Slave+To+Master+Access+Control)

## Build steps & pipeline functions

All operations listed here are compatible with both freestyle projects (Build steps) as well as pipeline projects (Pipeline functions).

### Sign with Jarsigner (`venafiCodeSignWithJarSigner`)

Signs one or more files with Java's [Jarsigner](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html) tool. It assumes that jarsigner is in PATH.

#### Example pipeline usage

~~~groovy
// Sign a single .jar file
venafiCodeSignWithJarSigner tppName: 'Main Demo Server',
    file: 'foo.jar',
    certLabel: 'my label'

// Sign multiple .jar files with a glob
venafiCodeSignWithJarSigner tppName: 'Main Demo Server',
    glob: '*.jar',
    certLabel: 'my label'
~~~

#### Required pipeline parameters

 * `tppName`: The Venafi Trust Protection Platform (TPP) to use for signing.
 * `file` or `glob`: Specifies the file(s) to sign, either through a single filename, or a glob.
 * `certLabel`: The label of the certificate (inside the TPP) to use for code signing. You can obtain a list of labels with `pkcs11config listcertificates`.

#### Optional pipeline parameters

 * `timestampingServers`: Specifies one or more timestamping authority servers to use during signing. Specifying this is strongly recommended, because it allows signed files to be usable even after the original signing certificate has expired.

    If you specify more than one server, then a random one will be used.

    Example:

    ~~~groovy
    venafiCodeSignWithJarSigner ..., timestampingServers: [
        [address: 'http://server1'],
        [address: 'http://server2']
    ]
    ~~~

    **Tip:** here are some public timestamping authorities that you can use:

     - http://timestamp.digicert.com
     - http://timestamp.globalsign.com
     - http://timestamp.comodoca.com/authenticode
     - http://tsa.starfieldtech.com

 * `extraArgs`: Specify extra custom CLI arguments to pass to Jarsigner.

    These arguments will be _appended_ to the Jarsigner CLI invocation, and take precedence over any arguments implicitly passed by this plugin.

    Example:

    ~~~groovy
    venafiCodeSignWithJarSigner ..., extraArgs: [
        [argument: '-arg1'],
        [argument: '-arg2']
    ]
    ~~~

 * `venafiClientToolsDir`: Specify the path to the directory in which Venafi CodeSign Protect client tools are installed. If not specified, it's autodetected as follows:

     - Linux: /opt/venafi/codesign
     - macOS: /Library/Venafi/CodeSigning
     - Windows: autodetected from the registry, or (if that fails): C:\Program Files\Venafi CodeSign Protect

### Verify with Jarsigner (`venafiVerifyWithJarSigner`)

Verifies one or more files with Java's [Jarsigner](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html) tool. It assumes that jarsigner is in PATH.

The node which performs the verification does not need to have pre-installed the certificate against which to verify. This function will fetch the certificate from the TPP, which is why it requires a certificate label.

#### Example pipeline usage

~~~groovy
// Verify a single .jar file
venafiVerifyWithJarSigner tppName: 'Main Demo Server',
    file: 'foo.jar',
    certLabel: 'my label'

// Verify multiple .jar files with a glob
venafiVerifyWithJarSigner tppName: 'Main Demo Server',
    glob: '*.jar',
    certLabel: 'my label'
~~~

#### Required pipeline parameters

 * `tppName`: The Venafi Trust Protection Platform (TPP) that contains the certificate that the signed file(s) were signed by.
 * `file` or `glob`: Specifies the file(s) to verify, either through a single filename, or a glob.
 * `certLabel`: The label of the certificate (inside the TPP) that was used for signing the file(s). You can obtain a list of labels with `pkcs11config listcertificates`.

#### Optional pipeline parameters

 * `venafiClientToolsDir`: Specify the path to the directory in which Venafi CodeSign Protect client tools are installed. If not specified, it's autodetected as follows:

     - Linux: /opt/venafi/codesign
     - macOS: /Library/Venafi/CodeSigning
     - Windows: autodetected from the registry, or (if that fails): C:\Program Files\Venafi CodeSign Protect

### Sign with Signtool (`venafiCodeSignWithSignTool`)

Signs one or more files with Microsoft's [Signtool](https://docs.microsoft.com/en-us/dotnet/framework/tools/signtool-exe) tool.

Important notes:

 * It assumes that signtool.exe is in PATH, unless you explicitly specify its path with `signToolPath`.
 * We use 'sha256' as the default signature digest algorithm, unlike Signtool's default ('sha1'). You may want to override this if you care about compatibility with older Windows versions that didn't support SHA-256.

#### Example pipeline usage

~~~groovy
venafiCodeSignWithSignTool tppName: 'Main Demo Server',
    fileOrGlob: 'foo.exe',
    subjectName: 'mydomain.com',
    timestampingServers: [[address: 'http://timestamp.digicert.com']]
~~~

#### Required pipeline parameters

 * `tppName`: The Venafi Trust Protection Platform (TPP) to use for signing.
 * `fileOrGlob`: A path or a glob that specifies the file(s) to be signed.
 * `subjectName` or `sha1`: Specifies the certificate (inside the TPP) to use for signing.

   You can either specify the certificate's Common Name ("Issued to" or "CN"), or its SHA-1 hash.

   You can obtain a list of Common Names with `cspconfig listcertificates` and checking what comes after `CN=`.

   Specifying the SHA-1 hash is useful if there are multiple certificates with the same Common Name.

#### Optional pipeline parameters

 * `timestampingServers`: Specifies one or more timestamping authority servers to use during signing. Specifying this is strongly recommended, because it allows signed files to be usable even after the original signing certificate has expired.

    If you specify more than one server, then a random one will be used.

    Example:

    ~~~groovy
    venafiCodeSignWithSignTool ..., timestampingServers: [
        [address: 'http://server1'],
        [address: 'http://server2']
    ]
    ~~~

    **Tip:** here are some public timestamping authorities that you can use:

     - http://timestamp.digicert.com
     - http://timestamp.globalsign.com
     - http://timestamp.comodoca.com/authenticode
     - http://tsa.starfieldtech.com

 * `signatureDigestAlgos`: The digest algorithm(s) to use to creating signatures.

    If none specified, 'sha256' is used as the default algorithm. This is very secure, but may not be compatible with older Windows versions. If you need compatibility with older Windows versions, you should specify 'sha1' and 'sha256' (in that order).

    When multiple digest algorithms are specified, they are applied in the order specified.

    Example:

    ~~~groovy
    venafiCodeSignWithSignTool ..., signatureDigestAlgos: [
        [algorithm: 'sha1'],
        [algorithm: 'sha256']
    ]
    ~~~

 * `appendSignatures` (boolean): If the target file(s) already have signatures, then append a new signature instead of overwriting the existing signatures.

 * `extraArgs`: Specify extra custom CLI arguments to pass to Signtool.

    These arguments will be _appended_ to the Signtool CLI invocation. If they overlap with any arguments implicitly passed by this plugin,
    then Signtool will raise an error.

    Example:

    ~~~groovy
    venafiCodeSignWithSignTool ..., extraArgs: [
        [argument: '/arg1'],
        [argument: '/arg2']
    ]
    ~~~

 * `signToolPath`: The full path to signtool.exe. If not specified, we assume that it's in PATH.

 * `venafiClientToolsDir`: Specify the path to the directory in which Venafi CodeSign Protect client tools are installed. If not specified, it's autodetected from the registry. If that fails, we fallback to <code>C:\Program Files\Venafi CodeSign Protect</code>.

 * `useMachineConfiguration` (boolean)

### Verify with Signtool (`venafiVerifyWithSignTool`)

Verifies one or more files with Microsoft's [Signtool](https://docs.microsoft.com/en-us/dotnet/framework/tools/signtool-exe) tool.

Important notes and caveats:

 * This function will automatically synchronize all certificates in the TPP with the local Windows certificate store.

   However, the first time this synchronization happens, Windows will pop up an interactive confirmation dialog. This means a human has to manually click on OK, before verification can proceed.

   If this is problematic, then there are two ways to solve this issue:

    - Ensure that the root certificate of the certificate that was used to sign the target file, is pre-installed.
    - In Aperture (the TPP web admin panel), configure the relevant TPP project, and disable the "Include Certificate Chain" option.

 * It assumes that signtool.exe is in PATH, unless you explicitly specify its path with `signToolPath`.

#### Example pipeline usage

~~~groovy
venafiVerifyWithSignTool tppName: 'Main Demo Server',
    fileOrGlob: 'foo.exe'
~~~

#### Required pipeline parameters

 * `tppName`: The Venafi Trust Protection Platform (TPP) that contains the certificate that the signed file(s) were signed by.

 * `fileOrGlob`: A path or a glob that specifies the file(s) to be verified.

#### Optional pipeline parameters

* `signToolPath`: The full path to signtool.exe. If not specified, we assume that it's in PATH.

 * `venafiClientToolsDir`: Specify the path to the directory in which Venafi CodeSign Protect client tools are installed. If not specified, it's autodetected from the registry. If that fails, we fallback to <code>C:\Program Files\Venafi CodeSign Protect</code>.

 * `useMachineConfiguration` (boolean)
