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
		def dockerImage = docker.image("storjlabs/ci:latest")
		dockerImage.pull()
		dockerImage.inside('-u root:root --cap-add SYS_PTRACE -v "/tmp/gomod":/go/pkg/mod') {
			try {
				stage('Build') {
					checkout scm
				}
				stage('Verification') {
					sh 'check-downgrades'
					sh 'go vet ./...'
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
