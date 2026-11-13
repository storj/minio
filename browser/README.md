# MinIO File Browser

``MinIO Browser`` provides minimal set of UI to manage buckets and objects on ``minio`` server. ``MinIO Browser`` is written in javascript and released under [Apache 2.0 License](./LICENSE).


## Installation

### Install node
```sh
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.34.0/install.sh | bash
exec -l $SHELL
nvm install stable
```

### Install node dependencies
```sh
npm install
```

## Generating Assets

```sh
npm run release
```

This generates `production` in the current directory. 


## Run MinIO Browser with live reload

### Run MinIO Browser with live reload

```sh
npm run dev
```

Open [http://localhost:8080/minio/](http://localhost:8080/minio/) in your browser to play with the application.

### Run MinIO Browser with live reload on custom port

```sh
npm run dev -- --port 8888
```

Open [http://localhost:8888/minio/](http://localhost:8888/minio/) in your browser to play with the application.

### Run MinIO Browser with live reload on any IP

```sh
npm run dev -- --host 0.0.0.0
```

Open [http://IP:8080/minio/](http://IP:8080/minio/) in your browser to play with the application.


## Run tests

    npm run test


## Docker development environment

This approach will download the sources on your machine such that you are able to use your IDE or editor of choice.
A Docker container will be used in order to provide a controlled build environment without messing with your host system.

### Prepare host system

Install [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) and [Docker](https://docs.docker.com/get-docker/).

### Development within container

Prepare and build container
```
git clone git@github.com:minio/minio.git
cd minio
docker build -t minio-dev -f Dockerfile.dev.browser .
```

Run container, build and run core
```sh
docker run -it --rm --name minio-dev -v "$PWD":/minio minio-dev

cd /minio/browser
npm install
npm run release
cd /minio
make
./minio server /data
```
Note `Endpoint` IP (the one which is _not_ `127.0.0.1`), `AccessKey` and `SecretKey` (both default to `minioadmin`) in order to enter them in the browser later.


Open another terminal.
Connect to container
```sh
docker exec -it minio-dev bash
```

Build and run frontend with auto-reload
```sh
cd /minio/browser
npm install
npm run dev -- --host 0.0.0.0
```

Open [http://IP:8080/minio/](http://IP:8080/minio/) in your browser to play with the application.

