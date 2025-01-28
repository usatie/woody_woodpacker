FROM amd64/ubuntu:22.04

# Install NASM and Binutils (for ld)
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y nasm binutils make vim build-essential bsdmainutils git valgrind gcc-multilib libc6-dev:i386

# Create a directory to store your assembly file
RUN mkdir WOODY_WOODPACKER
# Copy your assembly file into the container
COPY . WOODY_WOODPACKER
# Change the working directory
WORKDIR /WOODY_WOODPACKER

# Default command: run the resulting program
CMD ["bash"]
