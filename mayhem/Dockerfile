FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential sudo

COPY . /repo
WORKDIR /repo
RUN chmod +x createDebFromSourceUbuntu.bash
RUN ./createDebFromSourceUbuntu.bash --prefix=/install

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
ENV LD_LIBRARY_PATH=/install/lib