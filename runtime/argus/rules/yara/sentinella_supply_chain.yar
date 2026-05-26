/*
    Sentinella ARGUS Intelligence Pack — Software Supply Chain Attack Detection
    Category: deception
    Version: 2026.1
    Author: Sentinella
    License: GPL-2.0

    Detects software supply chain attack indicators including typosquatted
    packages, malicious install scripts, dependency confusion, compromised
    update mechanisms, and build artifact tampering.
*/

rule supply_chain_typosquatted_npm_package {
    meta:
        description = "ARGUS detected references to known typosquatted npm package names — attackers register near-identical package names to trick developers into installing malicious dependencies."
        severity = "critical"
        weight = 28
        category = "deception"
        author = "Sentinella"

    strings:
        // Common typosquats of popular npm packages
        $typo1 = "loadsh" ascii          // lodash
        $typo2 = "cross-env2" ascii      // cross-env
        $typo3 = "crossenv" ascii        // cross-env
        $typo4 = "babelcli" ascii        // babel-cli
        $typo5 = "event-stream2" ascii   // event-stream
        $typo6 = "electorn" ascii        // electron
        $typo7 = "reqeusts" ascii        // requests (npm/PyPI crossover)
        $typo8 = "coloures" ascii        // colors
        $typo9 = "chak" ascii            // chalk
        $typo10 = "axois" ascii          // axios
        $typo11 = "reacct" ascii         // react
        $typo12 = "expresss" ascii       // express

        // Package manifest indicators
        $pkg_json = "package.json" ascii
        $npm_registry = "registry.npmjs.org" ascii
        $node_modules = "node_modules" ascii

    condition:
        2 of ($typo*) or
        (any of ($typo*) and any of ($pkg_json, $npm_registry, $node_modules))
}

rule supply_chain_typosquatted_pypi_package {
    meta:
        description = "ARGUS detected references to known typosquatted PyPI package names — attackers impersonate popular Python libraries to distribute malware through pip install."
        severity = "critical"
        weight = 28
        category = "deception"
        author = "Sentinella"

    strings:
        // Common typosquats of popular PyPI packages
        $typo1 = "reqeusts" ascii       // requests
        $typo2 = "requestes" ascii      // requests
        $typo3 = "python-dateutils" ascii  // python-dateutil
        $typo4 = "cryptograpy" ascii    // cryptography
        $typo5 = "beautifulsoup" ascii  // beautifulsoup4 (ambiguity abuse)
        $typo6 = "numpyy" ascii         // numpy
        $typo7 = "colorsama" ascii      // colorama
        $typo8 = "opencvv" ascii        // opencv-python
        $typo9 = "djanga" ascii         // django
        $typo10 = "flaskk" ascii        // flask
        $typo11 = "skleran" ascii       // sklearn

        // PyPI/pip indicators
        $setup_py = "setup.py" ascii
        $pypi = "pypi.org" ascii
        $pip_install = "pip install" ascii nocase

    condition:
        2 of ($typo*) or
        (any of ($typo*) and any of ($setup_py, $pypi, $pip_install))
}

rule supply_chain_malicious_install_script {
    meta:
        description = "ARGUS detected a package install script executing suspicious commands — malicious postinstall/preinstall hooks are a primary vector for supply chain attacks."
        severity = "high"
        weight = 25
        category = "deception"
        author = "Sentinella"

    strings:
        // npm lifecycle hooks
        $hook1 = "\"preinstall\"" ascii
        $hook2 = "\"postinstall\"" ascii
        $hook3 = "\"preuninstall\"" ascii
        $hook4 = "\"install\"" ascii

        // Suspicious commands in install scripts
        $cmd1 = "curl " ascii
        $cmd2 = "wget " ascii
        $cmd3 = "Invoke-WebRequest" ascii nocase
        $cmd4 = "powershell" ascii nocase
        $cmd5 = "cmd.exe" ascii nocase
        $cmd6 = "/bin/sh" ascii
        $cmd7 = "/bin/bash" ascii
        $cmd8 = "eval(" ascii
        $cmd9 = "child_process" ascii
        $cmd10 = "exec(" ascii

        // Exfiltration / C2 indicators in install context
        $exfil1 = "os.environ" ascii
        $exfil2 = "process.env" ascii
        $exfil3 = "hostname" ascii nocase
        $exfil4 = "whoami" ascii

    condition:
        any of ($hook*) and
        (2 of ($cmd*) or (any of ($cmd*) and any of ($exfil*)))
}

rule supply_chain_dependency_confusion {
    meta:
        description = "ARGUS detected dependency confusion indicators — attackers publish higher-versioned public packages to override legitimate internal/private packages during install."
        severity = "high"
        weight = 22
        category = "deception"
        author = "Sentinella"

    strings:
        // Private registry references alongside public
        $private1 = "registry.npmjs.org" ascii
        $private2 = "artifactory" ascii nocase
        $private3 = "nexus" ascii nocase
        $private4 = "verdaccio" ascii nocase
        $private5 = "npm.pkg.github.com" ascii
        $private6 = "pkgs.dev.azure.com" ascii

        // Scope confusion indicators
        $scope1 = "\"name\": \"@" ascii
        $scope2 = "publishConfig" ascii
        $scope3 = "\"private\": false" ascii

        // Abnormally high version numbers used in confusion attacks
        $ver_high1 = "\"version\": \"99." ascii
        $ver_high2 = "\"version\": \"100." ascii
        $ver_high3 = "\"version\": \"999." ascii
        $ver_high4 = "version='99." ascii
        $ver_high5 = "version='100." ascii

    condition:
        any of ($ver_high*) and any of ($private*) or
        (any of ($ver_high*) and any of ($scope*))
}

rule supply_chain_compromised_update_mechanism {
    meta:
        description = "ARGUS detected a suspicious self-update mechanism — compromised update channels are used to distribute malware to existing installations of legitimate software."
        severity = "high"
        weight = 20
        category = "deception"
        author = "Sentinella"

    strings:
        // Update mechanism strings
        $update1 = "auto-update" ascii nocase
        $update2 = "selfUpdate" ascii
        $update3 = "checkForUpdates" ascii
        $update4 = "update-check" ascii
        $update5 = "updateUrl" ascii
        $update6 = "update_url" ascii

        // Suspicious download patterns
        $dl1 = "pastebin.com" ascii nocase
        $dl2 = "raw.githubusercontent.com" ascii
        $dl3 = "cdn.discordapp.com" ascii nocase
        $dl4 = "transfer.sh" ascii nocase
        $dl5 = "anonfiles" ascii nocase
        $dl6 = "gofile.io" ascii nocase
        $dl7 = "temp.sh" ascii nocase

        // Code execution after download
        $exec1 = "eval(" ascii
        $exec2 = "exec(" ascii
        $exec3 = "spawn(" ascii
        $exec4 = "execSync" ascii
        $exec5 = "Function(" ascii

    condition:
        any of ($update*) and
        any of ($dl*) and
        any of ($exec*)
}

rule supply_chain_fake_registry_url {
    meta:
        description = "ARGUS detected references to fake or suspicious package registry URLs — attackers host malicious packages on lookalike registries to intercept package installations."
        severity = "high"
        weight = 22
        category = "deception"
        author = "Sentinella"

    strings:
        // Fake/suspicious registry URLs
        $fake1 = "registry.npmmjs.org" ascii      // typosquat npmjs
        $fake2 = "registry.npm-js.org" ascii
        $fake3 = "registry.npmjs.com" ascii        // .com instead of .org
        $fake4 = "pypi.python.com" ascii           // fake pypi
        $fake5 = "pypl.org" ascii                  // typosquat pypi
        $fake6 = "crates-io.org" ascii             // fake crates.io
        $fake7 = "registry.yarnpkg.org" ascii      // fake yarn
        $fake8 = "npmregistry.com" ascii
        $fake9 = "npm-registry.org" ascii
        $fake10 = "pypii.org" ascii

        // .npmrc / pip.conf manipulation
        $config1 = ".npmrc" ascii
        $config2 = "pip.conf" ascii
        $config3 = "registry=" ascii
        $config4 = "index-url" ascii

    condition:
        any of ($fake*) or
        (2 of ($config*) and any of ($fake*))
}

rule supply_chain_build_artifact_tampering {
    meta:
        description = "ARGUS detected build artifact tampering indicators — attackers modify CI/CD pipelines or build outputs to inject malicious code into trusted software releases."
        severity = "high"
        weight = 24
        category = "deception"
        author = "Sentinella"

    strings:
        // CI/CD pipeline manipulation
        $ci1 = "GITHUB_TOKEN" ascii
        $ci2 = "ACTIONS_RUNTIME_TOKEN" ascii
        $ci3 = "CI_JOB_TOKEN" ascii
        $ci4 = "GITLAB_TOKEN" ascii
        $ci5 = "JENKINS_SECRET" ascii
        $ci6 = "NPM_TOKEN" ascii
        $ci7 = "PYPI_TOKEN" ascii

        // Build system tampering
        $build1 = "webpack.config" ascii
        $build2 = "rollup.config" ascii
        $build3 = "Makefile" ascii
        $build4 = "CMakeLists" ascii

        // Suspicious injection patterns
        $inject1 = "require('child_process')" ascii
        $inject2 = "import subprocess" ascii
        $inject3 = "os.system(" ascii
        $inject4 = "__import__(" ascii
        $inject5 = "compile(" ascii

        // Token exfiltration
        $exfil1 = "process.env" ascii
        $exfil2 = "os.environ" ascii
        $exfil3 = "btoa(" ascii
        $exfil4 = "base64" ascii nocase

    condition:
        2 of ($ci*) and any of ($inject*) or
        (any of ($ci*) and any of ($inject*) and any of ($exfil*)) or
        (any of ($build*) and any of ($inject*) and any of ($exfil*))
}
