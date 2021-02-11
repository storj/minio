#!/bin/bash
#
#  Mint (C) 2017 Minio, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

if [ $# -eq 0 ]
then
    ./mint.sh aws-sdk-go aws-sdk-php awscli security aws-sdk-java aws-sdk-ruby s3cmd &
    #these tests are disabled in their entirety by STORJ: mc minio-dotnet minio-java minio-js minio-py
else
    ./mint.sh "$@" &
fi

# Get the pid to be used for kill command if required
main_pid="$!"
trap 'echo -e "\nAborting Mint..."; kill $main_pid' SIGINT SIGTERM
# use -n here to catch mint.sh exit code, notify to ci
wait -n
