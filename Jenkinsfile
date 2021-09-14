@Library("nc-pipeline-lib-v1")
import jenkins.*

ncBuild(jdk: 'JDK11',
        maven: 'Maven 3.5.x',
        slackChannel: '#security-tools',
        bitbucketProject: 'WSCY',
        bitbucketRepository: 'aem-security-checker',
        releaseStrategy: 'simple',
        releaseVersionMappingToJira: 'pickaxe %v') {

    stageCheckout()

    stageBuild()

    stageDeployToNexus()
}