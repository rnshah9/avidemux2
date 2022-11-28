FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential sudo clang

COPY . /repo
WORKDIR /repo
RUN chmod +x createDebFromSourceUbuntu.bash
RUN ./createDebFromSourceUbuntu.bash --deps-only
RUN chmod +x bootStrap.bash
RUN ./bootStrap.bash --without-qt
RUN cp -r /repo/install/ /install/
RUN clang++ /repo/mayhem/fuzz_ADM_splitString.cpp -fsanitize=fuzzer,address -L /install/usr/lib/ -lADM_coreUtils6 -rpath /install/usr/lib/ -o /fuzz

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libsqlite3-dev \
    libxv-dev libvdpau-dev libva-dev \
    libasound2-dev libpulse-dev \
    qttools5-dev-tools qtbase5-dev \
    libx264-dev libxvidcore-dev \
    libmp3lame-dev libtwolame-dev libopus-dev libvorbis-dev libogg-dev \
    libpng-dev libfontconfig1-dev libfribidi-dev libaften-dev libfaac-dev libfdk-aac-dev libx265-dev libvpx-dev libaom-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_ADM_splitString
ENV LD_LIBRARY_PATH=/install/usr/lib