# Alpine Linux is a minimal Linux distribution, much smaller than typical distros (~5MB base).
# This specific tag includes the Go compiler/toolchain pre-installed on top of Alpine.
# We name this stage "build" so the runtime stage can reference it later.
# IMPORTANT: this FROM starts a completely separate, temporary image. Everything we
# do in this stage (source code, go.mod, the compiler itself) lives ONLY here and will
# be discarded once the build finishes - none of it automatically carries over to the
# next stage below.
FROM golang:1.27.0-alpine AS build

# Sets the working directory inside THIS stage's filesystem to /src.
# Every relative path below (like "./") now resolves to /src, not the root.
# We bother setting this instead of just using the image's default directory (usually "/")
# so that: (1) all our COPY/RUN commands can use short relative paths instead of
# repeating "/src/..." everywhere, and (2) the build stage's files are isolated into
# their own clearly-named folder rather than cluttering the filesystem root. The actual
# name "/src" is just a convention - it could be called anything - but it helps readability
# to visually associate this directory with "where the source code lives".
WORKDIR /src

# Copy just go.mod and go.sum (dependency manifests) from your project into /src.
# Here "./" means "/src/" because of the WORKDIR above.
COPY go.mod go.sum ./

# Download all Go module dependencies listed in go.mod/go.sum into Go's module cache.
# Doing this BEFORE copying all source code means Docker can cache this layer -
# if only your .go files change (not go.mod/go.sum), this slow download step is skipped on rebuild.
RUN go mod download

# Now copy the rest of the project source code into /src (the "." destination).
# The "." source refers to the "build context" - when you run `docker build .`,
# that trailing "." tells Docker "bundle up this entire directory on my machine
# (recursively) and make it available to COPY/ADD instructions." So "." here means
# "everything in the project folder you ran the build from" (cmd/, internal/, web/,
# attacker-lab/, data/, go.mod, etc.), except anything excluded by a .dockerignore file.
# This source code only exists in THIS build-stage image. It will NOT be present in the
# final runtime image/container below unless we explicitly COPY --from=build it over -
# and we never do that for the source code itself, only for the compiled binaries.
COPY . .

# Compile two binaries:
# CGO_ENABLED=0 disables cgo, which means the binary won't link against C libraries (like glibc).
# This produces a fully "static" binary that can run on a minimal base image like Alpine
# without needing matching system libraries present - otherwise you could hit
# "exec format error" or missing .so library errors at runtime.
# -trimpath strips local filesystem paths (like /src/...) from the compiled binary,
# which avoids leaking build machine details and makes builds more reproducible.
# -o /out/bearly-secure sets the OUTPUT path and filename for the compiled binary.
# ./cmd/server is the SOURCE package being compiled (your main.go entry point for the server).
# We chain a second build with && so both binaries compile in a single RUN layer.
RUN CGO_ENABLED=0 go build -trimpath -o /out/bearly-secure ./cmd/server && CGO_ENABLED=0 go build -trimpath -o /out/bearly-attacker-lab ./cmd/attackerlab

# Start a brand NEW, separate stage from a minimal Alpine Linux base image (no Go toolchain here).
# This is a fresh, independent image - it does NOT inherit the filesystem of the "build"
# stage above. Source code, go.mod, and the Go compiler from the build stage are left
# behind entirely; only files we explicitly COPY --from=build below will cross over.
# This final stage's filesystem is exactly what ends up in the Docker image you tag,
# and exactly what every container run from that image will contain.
# Alpine is not a kernel image - no container ships a kernel at all, they all share the
# host machine's kernel. "Alpine" refers to its small userspace: musl libc instead
# of glibc, busybox instead of GNU coreutils, which is why it's so much smaller than
# Ubuntu/Debian-based images.
FROM alpine:3.22

# apk is Alpine's package manager (like apt on Ubuntu or brew on Mac).
# "add --no-cache ca-certificates" installs the ca-certificates package without
# keeping the package index cached afterward (keeps image size down).
# CA certificates are a bundle of trusted root certificates (from Certificate Authorities
# like Let's Encrypt or DigiCert) used to verify the identity of remote HTTPS servers.
# Example: if this app calls out to a third-party API over HTTPS (like a payment
# processor), that external server presents its own TLS certificate during the
# connection. The app checks that certificate against this trusted CA bundle installed
# in the container to confirm the server is legitimate, not an impostor. Without this
# package, those outbound HTTPS calls would fail certificate verification entirely.
# addgroup -S bearly creates a new group named "bearly".
# adduser -S -G bearly bearly creates a new user named "bearly" (the final "bearly")
# whose primary group is set to "bearly" via -G bearly.
# In both commands, -S means "system account": no password, and for the user, no
# home directory - the standard convention for service accounts that only run a
# process and never log in interactively.
RUN apk add --no-cache ca-certificates && addgroup -S bearly && adduser -S -G bearly bearly

# Set the working directory for this runtime stage to /app.
# This is a fresh filesystem from the build stage - /src and everything in it is gone.
WORKDIR /app

# Copy ONLY the two compiled binaries from the "build" stage's /out/ directory
# into this stage's /app/ directory. --from=build tells Docker to pull these
# files from the other stage's filesystem instead of your local build context.
# This is the one and only bridge between the two stages - and we deliberately only
# bring over the compiled binaries, never the source code.
COPY --from=build /out/bearly-secure /out/bearly-attacker-lab ./

# Copy the attacker-lab static assets (HTML/CSS/JS) from your local project
# into /app/attacker-lab in the image, preserving the folder name.
COPY attacker-lab/ ./attacker-lab/

# Copy the web assets (templates, public files) from your local project
# into /app/web in the image, preserving the folder name.
COPY web/ ./web/

# Copy the seed PDF file into /app/data/uploads/.
# --chown=bearly changes the OWNER of the copied file(s) to the "bearly" user as part
# of the copy, instead of leaving them owned by root. This matters because the app
# runs as "bearly" later, and needs permission to read/write these files.
COPY --chown=bearly data/uploads/mystery-shack-tax-exemption.pdf ./data/uploads/

# Switch the active user for all subsequent instructions IN THIS DOCKERFILE (any further
# RUN/COPY steps would execute as this user too, though we have none left) and for the
# eventual running container, from the default "root" to the unprivileged "bearly" user
# created above.
# Every running process has a UID attached to it by the kernel - set by whichever USER
# was active when it launched. The kernel checks that UID (not the binary file's own
# ownership) against standard file permissions every time the process tries to read,
# write, or otherwise act on something. So "bearly can only touch what bearly owns"
# really means: the running bearly-secure process carries bearly's UID, and the kernel
# enforces access rules against that UID for every operation it attempts.
# This limits what a compromised process can do: it can't install packages, modify
# other files/processes, or read data it doesn't own. It also closes off many
# container-escape techniques that rely on root privileges inside the container as
# a starting point to break out and compromise the host machine.
USER bearly

# Define the command that runs when the container starts: execute the compiled
# bearly-secure binary directly (no shell wrapper, no `go run`, just the binary).
# CMD doesn't execute at build time - it just records what command to run later. When a
# container is eventually started from this image, that command inherits whatever USER
# was last set (bearly), so the resulting process (the running instance of this binary,
# distinct from the binary file on disk) runs as bearly, not root.
CMD ["./bearly-secure"]