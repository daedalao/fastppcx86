#!/usr/bin/env bash
# Build a clean x86_64 Arch Linux rootfs for FastPPCx86.
#
# Everything happens inside an unprivileged user namespace (bubblewrap), so this
# needs no root, no chroot and installs nothing on the host. The rootfs is built
# from Arch's official bootstrap tarball and never copies anything from the
# machine running the script, which is what makes the result safe to publish:
# no home directory, no configs, no keys, no history, no hostname.
#
# Requires: bwrap, curl, bsdtar (libarchive), zstd. All of them read-only.
# Produces: a squashfs image plus a sha256 file, built by tools installed inside
# the rootfs itself.
#
#   ./mkrootfs.sh [output-directory]
#
# Run it on any x86_64 host. On a POWER host the pacman step would need
# qemu-user or a FastPPCx86 that can already run pacman, which is a chicken and
# egg problem; build on x86_64 and copy the image over.

set -euo pipefail

OUTDIR="${1:-$PWD}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fastppcx86-rootfs.XXXXXX")"
ROOT="$WORK/root.x86_64"
MIRROR="${ARCH_MIRROR:-https://geo.mirror.pkgbuild.com}"
BOOTSTRAP="$MIRROR/iso/latest/archlinux-bootstrap-x86_64.tar.zst"
STAMP="$(date -u +%Y%m%d)"
IMAGE="$OUTDIR/fastppcx86-rootfs-arch-$STAMP.sqsh"
# Downloaded packages are kept outside the workspace so a rerun is cheap. It is
# bound in only for the pacman steps, never while sanitising or squashing, so
# the image never contains it and the teardown cannot reach it.
CACHE="${ROOTFS_PKG_CACHE:-$OUTDIR/.pkgcache}"
mkdir -p "$CACHE"

cleanup() {
  # Directories arrive from the tarball with modes that deny the invoking user
  # write access, so make the tree removable before deleting it.
  chmod -R u+rwX "$WORK" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Packages the guest needs to run games. Graphics and Vulkan are present so a
# guest works even when host thunks are not built; when they are, the thunk
# libraries take over at load time. lib32-* is not optional: the Steam client is
# 32-bit, and so are many older titles.
PACKAGES=(
  # base brings bash, coreutils, sed/grep/gawk, tar/gzip/bzip2/xz, findutils,
  # procps-ng, pciutils, file and glibc: everything launcher shell scripts use.
  base
  gcc-libs lib32-gcc-libs
  zlib lib32-zlib
  unzip zip

  # Graphics. Present so a guest renders even when host thunks are not built;
  # when they are, the thunk libraries take over at load time.
  mesa lib32-mesa
  libglvnd lib32-libglvnd
  vulkan-icd-loader lib32-vulkan-icd-loader
  libdrm lib32-libdrm
  libva lib32-libva
  vulkan-tools

  # X11 and Wayland client libraries
  libx11 lib32-libx11
  libxext lib32-libxext
  libxcb lib32-libxcb
  libxrandr lib32-libxrandr
  libxi lib32-libxi
  libxcursor lib32-libxcursor
  libxinerama lib32-libxinerama
  libxss lib32-libxss
  libxxf86vm lib32-libxxf86vm
  libxrender lib32-libxrender
  libxfixes lib32-libxfixes
  libxkbcommon lib32-libxkbcommon
  wayland lib32-wayland

  # Audio
  alsa-lib lib32-alsa-lib
  alsa-plugins lib32-alsa-plugins
  libpulse lib32-libpulse
  openal lib32-openal
  libvorbis lib32-libvorbis
  libogg lib32-libogg
  flac lib32-flac
  opus lib32-opus
  libsndfile lib32-libsndfile

  # Engine and launcher frameworks
  sdl2-compat lib32-sdl2-compat
  glib2 lib32-glib2
  gtk3 lib32-gtk3
  dbus lib32-dbus
  at-spi2-core lib32-at-spi2-core
  libcanberra lib32-libcanberra
  gdk-pixbuf2 lib32-gdk-pixbuf2

  # Controllers and hotplug: SDL needs libudev to see gamepads. The 32-bit
  # libudev/libsystemd pair ships in lib32-systemd, not a lib32-systemd-libs.
  systemd-libs lib32-systemd
  libusb lib32-libusb
  hidapi

  # Text and fonts
  freetype2 lib32-freetype2
  fontconfig lib32-fontconfig
  harfbuzz lib32-harfbuzz
  ttf-liberation ttf-dejavu

  # Images and video codecs games ship against
  libpng lib32-libpng
  libjpeg-turbo lib32-libjpeg-turbo
  libtheora lib32-libtheora
  libvpx lib32-libvpx

  # Networking and crypto: Steam, CEF and anything with an account system
  nss lib32-nss
  nspr lib32-nspr
  openssl lib32-openssl
  gnutls lib32-gnutls
  curl lib32-curl
  libxml2 lib32-libxml2
  expat lib32-expat
  sqlite lib32-sqlite
  icu lib32-icu

  # Desktop integration Steam expects to exist
  xdg-utils
  desktop-file-utils
  hicolor-icon-theme
  xorg-xrandr
)


echo ">>> workspace $WORK"

echo ">>> fetching Arch bootstrap"
curl -fL --progress-bar -o "$WORK/bootstrap.tar.zst" "$BOOTSTRAP"

echo ">>> extracting"
# --no-same-owner because this runs unprivileged; ownership inside the image is
# fixed up by mksquashfs below, which is told to force root:root.
bsdtar -C "$WORK" --no-same-owner -xf "$WORK/bootstrap.tar.zst"
[ -d "$ROOT" ] || { echo "bootstrap layout changed: no $ROOT" >&2; exit 1; }

# A mirror has to be chosen before pacman will do anything.
echo "Server = $MIRROR/\$repo/os/\$arch" > "$ROOT/etc/pacman.d/mirrorlist"

# pacman drops privileges to the alpm user to download, which needs a uid that
# exists in the namespace. Only uid 0 is mapped here, so the chown fails with
# EINVAL; download as root instead.
sed -i 's/^ *DownloadUser/#DownloadUser/' "$ROOT/etc/pacman.conf"

# Steam and 32-bit titles need multilib.
if ! grep -q '^\[multilib\]' "$ROOT/etc/pacman.conf"; then
  printf '\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n' >> "$ROOT/etc/pacman.conf"
fi

# Run a command inside the rootfs as uid 0. --unshare-user maps this user to
# root inside the namespace only; nothing on the host is writable except $ROOT.
in_root() {
  bwrap \
    --unshare-user --uid 0 --gid 0 \
    --unshare-ipc --unshare-pid --unshare-uts \
    --bind "$ROOT" / \
    --dev /dev --proc /proc --tmpfs /tmp --tmpfs /run \
    --ro-bind /etc/resolv.conf /etc/resolv.conf \
    --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/bin \
    --setenv LANG C.UTF-8 \
    --die-with-parent \
    "$@"
}

# Same namespace, plus the host package cache. Used only for pacman steps.
in_root_install() {
  bwrap \
    --unshare-user --uid 0 --gid 0 \
    --unshare-ipc --unshare-pid --unshare-uts \
    --bind "$ROOT" / \
    --bind "$CACHE" /var/cache/pacman/pkg \
    --dev /dev --proc /proc --tmpfs /tmp --tmpfs /run \
    --ro-bind /etc/resolv.conf /etc/resolv.conf \
    --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/bin \
    --setenv LANG C.UTF-8 \
    --die-with-parent \
    "$@"
}

echo ">>> initialising pacman keyring"
in_root pacman-key --init
in_root pacman-key --populate archlinux

echo ">>> installing packages"
in_root_install pacman -Syu --noconfirm --needed "${PACKAGES[@]}"

# Record exactly what went in. Useful for reproducing an image and for telling
# users what they have without mounting it.
in_root pacman -Q > "$WORK/manifest.txt"
install -Dm644 "$WORK/manifest.txt" "$ROOT/etc/fastppcx86-rootfs-manifest"

echo ">>> generating locale"
echo 'en_US.UTF-8 UTF-8' > "$ROOT/etc/locale.gen"
in_root locale-gen
echo 'LANG=en_US.UTF-8' > "$ROOT/etc/locale.conf"
ln -sf /usr/share/zoneinfo/UTC "$ROOT/etc/localtime"

echo ">>> building the image (mksquashfs from inside the rootfs)"
in_root_install pacman -S --noconfirm --needed squashfs-tools

echo ">>> sanitising"
# Anything identifying, host-specific or regenerable comes out here. The rootfs
# was never populated from this machine, so this is belt and braces rather than
# a scrub, but it also keeps images byte-comparable between builds.
in_root rm -rf \
  /var/cache/pacman/pkg \
  /var/log \
  /etc/pacman.d/gnupg \
  /root/.bash_history \
  /root/.gnupg \
  /etc/ssh/ssh_host_* \
  /var/tmp/*
in_root mkdir -p /var/log /var/cache/pacman/pkg
# Written from the host side: inside the namespace these files carry modes that
# deny the write even as mapped root. Empty rather than absent, because systemd
# and dbus regenerate machine-id on first boot.
chmod u+w "$ROOT/etc/machine-id" 2>/dev/null || true
: > "$ROOT/etc/machine-id"
echo fastppcx86 > "$ROOT/etc/hostname"
# The keyring above held a private key generated on this machine.
# `pacman-key --init && pacman-key --populate archlinux` recreates it if the
# user wants to install packages into the rootfs later.

echo ">>> squashing"
# The image is written to a bound output directory rather than into the tree:
# the rootfs root is mode 0555 and, more importantly, the image must not end up
# inside the filesystem it is an image of. /out is excluded from the archive.
# -all-root so the published image does not carry this user's uid/gid, which is
# also what makes the build independent of who ran it.
bwrap \
  --unshare-user --uid 0 --gid 0 \
  --unshare-ipc --unshare-pid --unshare-uts \
  --bind "$ROOT" / \
  --bind "$OUTDIR" /out \
  --dev /dev --proc /proc --tmpfs /tmp --tmpfs /run \
  --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/bin \
  --die-with-parent \
  mksquashfs / "/out/$(basename "$IMAGE")" \
    -comp zstd -Xcompression-level 19 \
    -all-root -noappend \
    -e out proc sys dev run tmp var/cache/pacman/pkg

( cd "$OUTDIR" && sha256sum "$(basename "$IMAGE")" > "$(basename "$IMAGE").sha256" )
cp "$WORK/manifest.txt" "$IMAGE.manifest"

echo
echo "image:    $IMAGE"
echo "size:     $(du -h "$IMAGE" | cut -f1)"
echo "sha256:   $(cut -d' ' -f1 < "$IMAGE.sha256")"
echo "manifest: $IMAGE.manifest"
echo
echo "Install it with:"
echo "  mkdir -p ~/.local/share/fex-emu/RootFS"
echo "  cp $(basename "$IMAGE") ~/.local/share/fex-emu/RootFS/"
echo "  # then set RootFS to that filename in ~/.config/fex-emu/Config.json"
