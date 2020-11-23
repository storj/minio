def withDockerNetwork(Closure inner) {
	try {
		networkId = UUID.randomUUID().toString()
		sh "docker network create ${networkId}"
		inner.call(networkId)
	} finally {
		sh "docker network rm ${networkId}"
	}
}

timeout(time: 26, unit: 'MINUTES') {
	node {
		def dockerImage = docker.build("storj-ci", "--pull https://github.com/storj/ci.git")
		dockerImage.inside('-u root:root --cap-add SYS_PTRACE -v "/tmp/gomod":/go/pkg/mod') {
			try {
				stage('Build') {
					checkout scm
				}
			}
			catch(err) {
				throw err
			}
			finally {
				sh "chmod -R 777 ." // ensure Jenkins agent can delete the working directory
				deleteDir()
			}

		}
	}
}

