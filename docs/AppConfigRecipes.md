# Per-game AppConfig recipes

The config layering already gives us a per-title registry: a JSON at
`~/.config/fex-emu/AppConfig/<guest-binary-basename>.json` overrides the global
config for that title only. **Environment variables override AppConfig**, so a
launcher export always wins — and conversely, an AppConfig can silently disarm
a recipe you thought you enabled (see the trap below).

## The trap that voided a test session

`SMCChecks: "none"` in an AppConfig disables mtrack, and every fork SMC
feature (`SMCSoftInvalidate`, `SMCLazyInval`, `SMCSemanticPatch`) gates on
mtrack — they all stay silently off. Ziggurat's live config does exactly this.
`fexplay-smc`'s armed recipes therefore export `FEX_SMCCHECKS=mtrack`.
Before interpreting any per-title run, read its AppConfig first.

## Recipe templates

Copy, rename to the guest binary's basename + `.json`, adjust.

**Non-SMC title, maximum speed** (only if proven to never write code after
load — a wrong guess here produces stale-code corruption, cf. the Stardew
CoreCLR wedge that `SMCChecks: "none"` caused):

```json
{ "Config": { "SMCChecks": "none" } }
```

**Strict soft-invalidate (safe default for SMC-active titles):**

```json
{ "Config": { "SMCChecks": "mtrack", "SMCSoftInvalidate": "1" } }
```

**Semantic patching (JIT/patcher-heavy titles; both halves smcstorm-validated):**

```json
{ "Config": { "SMCChecks": "mtrack", "SMCSoftInvalidate": "1",
              "SMCSemanticPatch": "1", "SMCFileImmutable": "1" } }
```

**Lazy invalidation (cross-thread-codegen-heavy; sound since SMCLazyScrub):**

```json
{ "Config": { "SMCChecks": "mtrack", "SMCSoftInvalidate": "1",
              "SMCLazyInval": "1", "SMCFileImmutable": "1" } }
```

## Known-good deployed configs (op4k, 2026-08-03)

| Title (binary) | Config | Why |
|---|---|---|
| `Ziggurat.x86_64` | `SMCChecks: none`, asound thunk off | Historical tuning; runs. Means SMC recipes are inert for it unless the launcher forces mtrack. |
| `Stardew Valley` | `SMCChecks: mtrack`, `MaxInst: 50000`, `EnableCodeCachingWIP: 1` | CoreCLR needs mtrack (the `none` wedge); cache experiment. |

Production posture notes: the forensic tripwires (entry-block NoExec,
suspect-ExitFunctionLink) absorb by default as of b7ceb2de2; aborts are the
debugging opt-in (`FEX_NOEXEC_ABORT=1`, `FEX_EXITLINK_ABORT=1`).
