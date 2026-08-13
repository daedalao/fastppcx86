# Per-game AppConfig recipes

The config layering gives a per-title registry: a JSON file at
`~/.config/fex-emu/AppConfig/<guest-binary-basename>.json` overrides the global
config for that title only. Environment variables override AppConfig, so a
launcher export always wins.

Read [GAMING.md](GAMING.md) for what these knobs do. This file is the templates.

## The trap

An AppConfig can silently disarm a recipe you thought you enabled.

`"SMCChecks": "none"` turns off mtrack, and every SMC feature in this fork gates
on mtrack, so `SMCSoftInvalidate`, `SMCLazyInval` and `SMCSemanticPatch` all stay
off with no diagnostic. A title whose AppConfig sets it will ignore every SMC
recipe below.

Read a title's AppConfig before interpreting any measurement of it, and have
launcher scripts export `FEX_SMCCHECKS=mtrack` explicitly when they arm an SMC
recipe.

## Recipe templates

Copy, rename to the guest binary's basename plus `.json`, adjust.

**Non-SMC title, maximum speed.** Only when the title provably never writes code
after load. A wrong guess here produces stale-code corruption, which is what the
Stardew CoreCLR wedge was.

```json
{ "Config": { "SMCChecks": "none" } }
```

**Strict soft-invalidate.** The safe default for SMC-active titles.

```json
{ "Config": { "SMCChecks": "mtrack", "SMCSoftInvalidate": "1" } }
```

**Semantic patching.** For JIT and patcher-heavy titles (Mono, .NET).

```json
{ "Config": { "SMCChecks": "mtrack", "SMCSoftInvalidate": "1",
              "SMCSemanticPatch": "1", "SMCFileImmutable": "1" } }
```

**Lazy invalidation.** For titles whose code generation is cross-thread heavy.
Sound by default, because `SMCLazyScrub` defaults on. Pair it with `SMCLazyLink`:
without that, lazy invalidation turns off block-to-block linking, and
`ExitFunctionLink` then dominates the profile.

```json
{ "Config": { "SMCChecks": "mtrack", "SMCSoftInvalidate": "1",
              "SMCLazyInval": "1", "SMCLazyLink": "1",
              "SMCFileImmutable": "1" } }
```

The recipes stack, but each has more mileage alone than in combination. Prefer
semantic patching or lazy, and profile before assuming either is the answer.

## Non-SMC per-title options

**A title that requires AVX to launch.** AVX is hidden by default on this port.

```json
{ "Config": { "HostFeatures": "enableavx" } }
```

**A title that spends its time in frame-pointer-addressed locals**, which is all
32-bit code with `EBP` frame chains. `NonTSORBP` extends the existing
thread-private-stack TSO exemption from `RSP` to `RBP`. It carries the same
soundness caveat as that exemption, so it is a per-app opt-in and not a default.

```json
{ "Config": { "NonTSORBP": "1" } }
```

**Hardware TSO.** `HWTSO` is host-wide rather than per-title in character, but it
is settable here. It is sound where the kernel accepts `PROT_SAO` and falls back
automatically where it does not. See GAMING.md before enabling it on a host class
it has not been litmus-tested on.

```json
{ "Config": { "HWTSO": "1" } }
```

## Known-good deployed configs (op4k, 2026-08-03)

| Title (binary) | Config | Why |
|---|---|---|
| `Ziggurat.x86_64` | `SMCChecks: none`, asound thunk off | Historical tuning; runs. SMC recipes are inert for it unless the launcher forces mtrack. |
| `Stardew Valley` | `SMCChecks: mtrack`, `MaxInst: 50000`, `EnableCodeCachingWIP: 1` | CoreCLR needs mtrack (the `none` wedge); cache experiment. |

## Production posture

The forensic tripwires (entry-block NoExec, suspect-`ExitFunctionLink`) absorb by
default. Aborting on them is the debugging opt-in: `FEX_NOEXEC_ABORT=1` and
`FEX_EXITLINK_ABORT=1`. Both are tested for presence, not value, so unset them
rather than setting them to `0`.
