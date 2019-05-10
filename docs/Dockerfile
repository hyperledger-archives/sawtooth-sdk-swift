# Copyright 2019 Cargill Incorporated
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# docker build . -f docs/Dockerfile -t sawtooth-sdk-swift-docs
# docker run --rm -v $(pwd):/project/sawtooth-sdk-swift sawtooth-sdk-swift-docs

FROM swift:4.2

RUN apt-get update \
 && apt-get install -y \
 ruby-full \
 libsqlite3-dev

RUN git clone https://github.com/jpsim/SourceKitten.git \
 && cd SourceKitten \
 && swift build -c release --static-swift-stdlib \
 && mv .build/x86_64-unknown-linux/release/sourcekitten /usr/local/bin/

RUN gem install jazzy

WORKDIR /project/sawtooth-sdk-swift/

# `swift build` must be run in order for sourcekitten to parse the code.
# However, the build is expected to fail due to some frameworks being
# unavailable on Linux.
CMD swift build >/dev/null 2>&1; \
 sourcekitten doc --spm-module SawtoothSigning > tmp.json \
 && jazzy --clean  --sourcekitten-sourcefile tmp.json -o docs/jazzy/build \
 && rm tmp.json
