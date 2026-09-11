# kexec A/B between the 4K and 64K kernels on op64k

Derived from the "Session 4: THE KEXEC A/B" and "DECISIVE: 4K-page kernel from
the SAME final source is CLEAN" sections of `FINDINGS-64k-gpu.md`. That work
used the A/B to prove the amdgpu DMA bug followed the kernel's page size; the
same rig is what `PAGE_SIZE_64K_EXECUTION.md` §1 means by "both kernels are
verified for every stage", ~15 min per cycle.

**Nobody executes this from an agent session.** It needs BMC serial console
access and arrow-key timing during IPL. It is written down so the human driving
op64k can do a cycle without re-deriving it.

## What exists on the machine

One drive, two kernels, installed side by side. `grub` default stays 64K; the
4K kernel is reached only by a manual kexec from the petitboot shell.

| thing | path |
|---|---|
| 64K kernel (default boot) | the installed `linux` package, `7.2.0-books-64k` |
| 4K kernel, same 7.2.0-final source + same 3 patches | `/boot/vmlinux-4kfinal-diag` |
| 4K kernel, older 7.2.0-rc5 build | `/boot/vmlinux-linux-books-4k` |
| diagnostic initramfs | `/boot/initramfs-4kdiag.img`, `/boot/initramfs-4kfinal-diag.img` |
| initramfs recipe | `/etc/mkinitcpio-4kdiag.conf` — `MODULES=(amdgpu ext4)`, `HOOKS=(base udev modconf block)` |
| grub entry "4K-DIAG shell" | `/etc/grub.d/40_custom` |

Petitboot mounts the boot drive at `/var/petitboot/mnt/dev/sda1`, so the paths
above appear there as `/var/petitboot/mnt/dev/sda1/boot/...`.

## The constraint that shapes everything

**Root (`/`) is ext4 with a 65536-byte block size.** A 4K-page kernel cannot
mount it — the block size exceeds its page size. That is why the 4K side boots
`break=premount` into a busybox initramfs and never mounts root.

`/home` is `/dev/sdb1`, 4K-block, and mounts fine on both kernels. It is shared
with op4k, so the FEX tree, rootfs, wine build and game library are reachable
from the 4K side.

Consequences for FEX work:

- On the 64K side you get a full desktop: normal boot, X, sunshine, games.
- On the 4K side you get a busybox shell with `/home` and whatever you launch
  through an explicit `ld64.so.2` + library-closure invocation (the pattern
  `~/4kdiag/run.sh` uses for the GPU probes). **No systemd, no X, no display,
  no package tooling.** It is enough for `pageprobe`, `Bin/FEX /usr/bin/true`,
  ctest-style CLI runs and the microbench trio; it is not enough for a game lap.
- Therefore the 4K *performance* reference for S1/S2/S3 comes from **op4k**
  (the other host, 4K root), not from a kexec on op64k. The kexec A/B here is
  for *behaviour* questions — "does this die because of the page size?" — where
  holding the hardware, firmware and drive fixed is the whole point.
- If a same-session 4K game lap is ever needed on this hardware, the fix is a
  second root filesystem with a 4K block size, not a change to this procedure.

## Procedure: 64K -> 4K

1. On the 64K side, stage whatever the run needs under `/home` (binaries, a
   `run.sh`, the library closure). Nothing under `/` survives the switch.
2. Attach to the BMC serial console (SOL). You need to see IPL output.
3. `sudo reboot`.
4. **Spam the Down-arrow every ~4 s through IPL.** This cancels petitboot's
   autoboot and parks the cursor on "Exit to shell". Press Enter.
5. In the petitboot shell, load and jump:

   ```sh
   kexec -l /var/petitboot/mnt/dev/sda1/boot/vmlinux-4kfinal-diag \
     --initrd=/var/petitboot/mnt/dev/sda1/boot/initramfs-4kfinal-diag.img \
     --append="console=tty1 console=hvc0 break=premount pci=realloc \
               amdgpu.ppfeaturemask=0xfffd7fff loglevel=7"
   kexec -e
   ```

   Use `vmlinux-linux-books-4k` + `initramfs-4kdiag.img` for the rc5 build
   instead. Keep the `--append` line identical between the two sides of an A/B
   — the GPU investigation burned a cycle on a cmdline that differed.
6. At the `break=premount` busybox prompt:

   ```sh
   mkdir -p /mnt && mount /dev/sdb1 /mnt
   getconf PAGESIZE    # expect 4096
   sh /mnt/daedalao/<your-run>.sh
   ```

   `/mnt/daedalao` is `/home/daedalao` as seen from the other kernel; paths
   baked into scripts as `/home/daedalao/...` will NOT resolve. Either use
   `/mnt/daedalao/...` or `mkdir -p /home && mount --bind /mnt /home` first.

## Procedure: 4K -> 64K

`reboot` (or power-cycle from the BMC) and let petitboot autoboot the grub
default. Nothing needs undoing; the kexec leaves no persistent state.

## Rules for a valid A/B

- One variable. Same FEX binary, same cmdline, same `/home` contents, same
  power-on where possible. The GPU work's strongest result came from kexec'ing
  both kernels inside one power-on: same firmware, same drive, same skiboot
  instance, no PERST.
- Set the governor on **both** sides before recording anything —
  `Scripts/64k/governor-performance.sh`. op64k boots `ondemand`, and the
  busybox side boots whatever the driver defaults to.
- Record `getconf PAGESIZE` and `uname -r` at the top of every capture file so a
  mislabelled log is self-identifying.
- Run `pageprobe` first on each side. It is the cheapest proof you are on the
  kernel you think you are on.
- Never re-register binfmt against a scratch build (`binfmt-pinned-interpreter`).
  On op64k binfmt gets registered only at the S4 exit, pointing at
  `src/build-smc/Bin/FEX`. Until then launch FEX directly.
