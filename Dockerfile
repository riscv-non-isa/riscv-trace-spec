# Use an official Ubuntu as a parent image
FROM ubuntu:latest

# Set noninteractive mode for apt-get
ARG DEBIAN_FRONTEND=noninteractive

# Update and install latex, git, make and other required tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    texlive-latex-base \
    texlive-fonts-recommended \
    texlive-fonts-extra \
    texlive-latex-extra \
    lmodern \
    texlive-science \
    make \
    git && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /data

# By default, run a shell
CMD ["/bin/bash"]