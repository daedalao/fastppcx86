// SPDX-License-Identifier: MIT
#include "Recipes.h"

#include <algorithm>
#include <array>

namespace FastPPCx86::Launcher::Recipes {

namespace {
  // Option sets for the SMC recipes. Every recipe past "off" sets SMCCHECKS
  // explicitly rather than relying on the default, because an AppConfig left
  // over from an earlier experiment can otherwise set "none" underneath and
  // disarm the whole recipe with no diagnostic (docs/AppConfigRecipes.md).
  constexpr std::array<Option, 1> OffOptions {{{"SMCCHECKS", "none"}}};
  constexpr std::array<Option, 1> LegacyOptions {{{"SMCCHECKS", "mtrack"}}};
  constexpr std::array<Option, 2> StrictOptions {{{"SMCCHECKS", "mtrack"}, {"SMCSOFTINVALIDATE", "1"}}};
  constexpr std::array<Option, 4> SemanticOptions {
    {{"SMCCHECKS", "mtrack"}, {"SMCSOFTINVALIDATE", "1"}, {"SMCSEMANTICPATCH", "1"}, {"SMCFILEIMMUTABLE", "1"}}};
  constexpr std::array<Option, 5> LazyOptions {
    {{"SMCCHECKS", "mtrack"}, {"SMCSOFTINVALIDATE", "1"}, {"SMCLAZYINVAL", "1"}, {"SMCLAZYLINK", "1"}, {"SMCFILEIMMUTABLE", "1"}}};

  constexpr std::array<SMCRecipe, 5> Recipes {{
    {"off", "Off (SMCChecks=none)",
     "Turns the self-modifying-code tracker off entirely. Only for a title that provably never writes code after "
     "load -- a wrong guess produces stale-code corruption. Note this also disarms every other SMC option, since "
     "they all gate on mtrack.",
     OffOptions, true},
    {"legacy", "Legacy",
     "Every write to a tracked page invalidates and recompiles. Correct, and the baseline everything else is "
     "measured against.",
     LegacyOptions, false},
    {"strict", "Strict soft-invalidate",
     "Keeps the compiled code plus a hash of the bytes it came from, and relinks on the next dispatch when the "
     "bytes turn out unchanged. Only genuinely modified blocks recompile. Fully correct, modest gains -- the safe "
     "default for an SMC-active title.",
     StrictOptions, false},
    {"semantic", "Semantic patching",
     "Also recognises writes that only rewrite a branch target or an immediate inside an already-compiled block, "
     "and patches those into the translated code so the block stays live. Best first guess for Mono, .NET and "
     "other scripting-JIT titles.",
     SemanticOptions, false},
    {"lazy", "Lazy invalidation",
     "Defers invalidation to the next point the guest must serialise anyway, so the writing thread runs at full "
     "speed. Best for titles whose code generation is cross-thread heavy. Ships with lazy linking on: without it "
     "ExitFunctionLink became the hottest symbol in a Moonlighter profile at 7.3%, against 0.10% with it.",
     LazyOptions, false},
  }};

  constexpr std::array<std::string_view, 8> SMCOwnedKeys {
    "SMCCHECKS",    "SMCSOFTINVALIDATE", "SMCSEMANTICPATCH", "SMCFILEIMMUTABLE",
    "SMCLAZYINVAL", "SMCLAZYLINK",       "SMCLAZYSCRUB",     "SMCSTOREEMULATION",
  };

  constexpr std::array<std::string_view, 2> HostFeatureValues {"enableavx", "disableavx"};

  constexpr std::array<Knob, 14> KnobTable {{
    {"HOSTFEATURES", "AVX visibility",
     "AVX is hidden by default on this port: POWER's vector units are 128-bit, so every 256-bit YMM op is "
     "decomposed into a pair plus high-half spill traffic. Guest glibc string routines measured 36-67% faster on "
     "their SSE paths. Turn it on for titles that need it -- Witcher 3 will not load a save without it, which "
     "makes this a correctness setting there, not a performance one. Cyberpunk 2077 is measurably worse with it "
     "(+26% p99 frametime).",
     KnobKind::Choice, KnobGroup::Performance, "enableavx", HostFeatureValues, false},

    {"HWTSO",
     "Hardware TSO (PROT_SAO)",
     "Replaces per-access barrier emulation with POWER's Strong Access Ordering: the hardware orders the accesses "
     "and the JIT stops emitting TSO ops entirely. Sound -- zero violations in 16.3 million litmus rounds. "
     "Experimental only because it depends on the kernel honouring PROT_SAO; FEX probes at startup and falls back "
     "with a warning if it does not, so enabling it on a host that cannot do it costs nothing.",
     KnobKind::Toggle,
     KnobGroup::Performance,
     "1",
     {},
     false},

    {"SPINCOLLAPSE",
     "Spin-loop collapse (K)",
     "Batches the budget decrement of counted spin-poll loops so each iteration retires K units instead of one. "
     "The largest measured per-title win on this port: Cyberpunk 2077's benchmark scene went 17.43 -> 27.94 fps "
     "(+60%) at K=32, with p99 frametime down 52%. Note that leaving this unset is OFF, not K=32 -- the built-in "
     "default is the K value used once enabled, not a default enablement.",
     KnobKind::Integer,
     KnobGroup::Performance,
     "32",
     {},
     false},

    {"REPORTED_CPUS",
     "Guest-visible CPU count",
     "Forces the CPU count the guest sees, independent of the affinity cage. Use it when you want a small worker "
     "pool but a wide cage. The cage alone already bounds the reported count on current builds.",
     KnobKind::Integer,
     KnobGroup::Performance,
     "8",
     {},
     false},

    {"SPINLOOPCLAMPAUTO",
     "Automatic spin-loop clamping",
     "Short-circuits recognised library spin-wait loops. No longer required for correctness anywhere in the "
     "census, but it was short-circuiting around 1017 library spin loops in Ziggurat, so it remains a measurable "
     "performance opt-in.",
     KnobKind::Toggle,
     KnobGroup::Performance,
     "1",
     {},
     false},

    {"MONOHACKS",
     "Mono workarounds",
     "Enables the Mono-specific workarounds. Worth having on for Mono and Unity titles, and worth turning off when "
     "A/B testing whether one is still needed.",
     KnobKind::Toggle,
     KnobGroup::Performance,
     "1",
     {},
     false},

    {"MULTIBLOCK",
     "Multiblock compilation",
     "Compiles across block boundaries where it can. On by default in most configurations; exposed here so it can "
     "be turned off when bisecting a codegen problem.",
     KnobKind::Toggle,
     KnobGroup::Performance,
     "1",
     {},
     false},

    {"MAXINST",
     "Max instructions per block",
     "Caps how many guest instructions land in one translated block. Raising it helps titles with very large "
     "straight-line functions; lowering it reduces recompile cost on write-heavy code.",
     KnobKind::Integer,
     KnobGroup::Performance,
     "500",
     {},
     false},

    // -- Unsound ------------------------------------------------------------
    {"LOCKONLYTSO",
     "Lock-only TSO",
     "UNSOUND, and measured rather than theoretical. Restricts memory-ordering barriers to instructions carrying a "
     "LOCK prefix; plain loads and stores lose their barriers. The MP litmus shape, which x86 forbids outright, "
     "went from 0 observations in 150,000 rounds to 659 in 30,000. IRIW agrees: 552 in 1,000,000 against 0 in "
     "67,200,000. Anything in the guest doing its own lock-free work may silently compute wrong answers rather "
     "than crash. Costs about 1.6x in speed to be correct here.",
     KnobKind::Toggle,
     KnobGroup::Unsound,
     "1",
     {},
     false},

    {"NONTSORBP",
     "Non-TSO RBP",
     "Extends the existing thread-private-stack TSO exemption from RSP to RBP, which matters for the EBP frame "
     "chains all 32-bit code is built around. Carries exactly the caveat the RSP exemption carries: a guest that "
     "shares stack memory between threads and relies on x86 ordering for it will get wrong answers.",
     KnobKind::Toggle,
     KnobGroup::Unsound,
     "1",
     {},
     false},

    // -- Diagnostic ---------------------------------------------------------
    {"TSOPAIRELIDE",
     "Disable TSO pair elision",
     "Set to 0 to disable elision of the leading barrier in an adjacent TSO load/store pair. A bisection tool: use "
     "it to rule the elision pass in or out when a title misbehaves in a way that smells like memory ordering.",
     KnobKind::Choice,
     KnobGroup::Diagnostic,
     "0",
     {},
     false},

    {"VK_PROCADDR_TRACE",
     "Trace Vulkan proc addresses",
     "Logs every Vulkan entry point the guest successfully links. Useful when a Vulkan title fails at startup and "
     "you need to see what resolved. Presence-tested: setting it to 0 enables it just as 1 does, so it must be "
     "removed rather than set false.",
     KnobKind::Toggle,
     KnobGroup::Diagnostic,
     "1",
     {},
     true},

    {"NO_THUNK_PARTIAL_FILL",
     "Disable partial thunk refill",
     "Restores the full GPR refill on thunk and host-call crossings. Suspect it when a crash lands in or just "
     "after a thunk call. Presence-tested: remove it to disable, do not set it to 0.",
     KnobKind::Toggle,
     KnobGroup::Diagnostic,
     "1",
     {},
     true},

    {"X11_SYNC_EVERY_CALL",
     "X11 sync on every call",
     "Restores a guest XSync on every Display-taking call, which was the default until 2026-08-13. Set it when "
     "bisecting a BadDrawable or BadMatch at GL bootstrap or a mode change.",
     KnobKind::Toggle,
     KnobGroup::Diagnostic,
     "1",
     {},
     false},
  }};
} // namespace

std::span<const SMCRecipe> SMC() {
  return Recipes;
}

std::span<const std::string_view> SMCKeys() {
  return SMCOwnedKeys;
}

const SMCRecipe* FindSMC(std::string_view Id) {
  for (const auto& Recipe : Recipes) {
    if (Recipe.Id == Id) {
      return &Recipe;
    }
  }
  return nullptr;
}

std::string_view ClassifySMC(const std::map<std::string, std::string>& Fex) {
  // Collect only the keys the recipes own, so unrelated tuning does not stop a
  // title from being recognised as "strict" or "lazy".
  std::map<std::string, std::string> Owned;
  for (const auto& Key : SMCOwnedKeys) {
    if (const auto Found = Fex.find(std::string {Key}); Found != Fex.end()) {
      Owned.insert(*Found);
    }
  }

  if (Owned.empty()) {
    return "unset";
  }

  for (const auto& Recipe : Recipes) {
    if (Owned.size() != Recipe.Options.size()) {
      continue;
    }
    const bool Matches = std::all_of(Recipe.Options.begin(), Recipe.Options.end(), [&Owned](const Option& O) {
      const auto Found = Owned.find(std::string {O.Key});
      return Found != Owned.end() && Found->second == O.Value;
    });
    if (Matches) {
      return Recipe.Id;
    }
  }

  return "custom";
}

void ApplySMC(std::map<std::string, std::string>& Fex, std::string_view RecipeId) {
  for (const auto& Key : SMCOwnedKeys) {
    Fex.erase(std::string {Key});
  }
  if (RecipeId == "unset") {
    return;
  }
  if (const SMCRecipe* Recipe = FindSMC(RecipeId)) {
    for (const auto& O : Recipe->Options) {
      Fex[std::string {O.Key}] = std::string {O.Value};
    }
  }
}

std::span<const Knob> Knobs() {
  return KnobTable;
}

const Knob* FindKnob(std::string_view Key) {
  for (const auto& K : KnobTable) {
    if (K.Key == Key) {
      return &K;
    }
  }
  return nullptr;
}

void SetKnob(std::map<std::string, std::string>& Fex, const Knob& K, bool On, std::string_view Value) {
  const std::string Key {K.Key};
  if (!On) {
    // Erase rather than write a falsey value. For a presence-tested switch that
    // distinction is the whole ballgame -- FEX_VK_PROCADDR_TRACE=0 enables it --
    // and erasing is correct for the value-tested ones too, since it restores
    // whatever the config layers below would otherwise have said.
    Fex.erase(Key);
    return;
  }
  Fex[Key] = Value.empty() ? std::string {K.OnValue} : std::string {Value};
}

bool KnobIsOn(const std::map<std::string, std::string>& Fex, const Knob& K) {
  const auto Found = Fex.find(std::string {K.Key});
  if (Found == Fex.end()) {
    return false;
  }
  if (K.PresenceTested) {
    // Present at all means on, whatever the value says.
    return true;
  }
  if (K.Kind == KnobKind::Toggle) {
    return Found->second != "0" && !Found->second.empty();
  }
  return true;
}

} // namespace FastPPCx86::Launcher::Recipes
