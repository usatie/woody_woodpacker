FROM amd64/ubuntu:latest

# Install NASM and Binutils (for ld)
RUN apt-get update && apt-get install -y nasm binutils make vim build-essential

# Create a directory to store your assembly file
RUN mkdir WOODY_WOODPACKER
# Copy your assembly file into the container
COPY . WOODY_WOODPACKER
# Change the working directory
WORKDIR /WOODY_WOODPACKER

# Default command: run the resulting program
CMD ["bash"]
