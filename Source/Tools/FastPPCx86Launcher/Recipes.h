// SPDX-License-Identifier: MIT
#pragma once

#include <map>
#include <span>
#include <string>
#include <string_view>

/**
 * The tuning presets, and the individual knobs worth exposing.
 *
 * Every entry here is transcribed from docs/GAMING.md and the option names are
 * checked against docs/ENV_REFERENCE.md and the source. The `Summary` strings
 * are the reason each knob exists, and they are meant to be shown in the UI: a
 * launcher that offers `LockOnlyTSO` without saying it produces measurably wrong
 * answers is worse than one that does not offer it at all.
 *
 * Keys are bare option names. A key `SMCCHECKS` is exported as `FEX_SMCCHECKS`.
 */
namespace FastPPCx86::Launcher::Recipes {

struct Option {
  std::string_view Key;
  std::string_view Value;
};

struct SMCRecipe {
  std::string_view Id;
  std::string_view Name;
  std::string_view Summary;
  std::span<const Option> Options;
  /// True when selecting this can silently corrupt a title that does write code.
  bool Risky {false};
};

/// Mutually exclusive; ordered from least to most aggressive.
std::span<const SMCRecipe> SMC();
const SMCRecipe* FindSMC(std::string_view Id);

/// Which recipe the given option set corresponds to, or "custom" when it matches
/// none of them exactly. Empty input yields "unset".
std::string_view ClassifySMC(const std::map<std::string, std::string>& Fex);

/// Replaces every SMC-related key in `Fex` with the chosen recipe's options.
void ApplySMC(std::map<std::string, std::string>& Fex, std::string_view RecipeId);

enum class KnobKind {
  Toggle,  ///< On/off, written as Value when on.
  Integer, ///< Free integer, e.g. SpinCollapse's K.
  Choice,  ///< One of Values.
};

enum class KnobGroup {
  Performance, ///< Worth trying on a title that runs but is slow.
  Unsound,     ///< Produces results x86 says are impossible. Measured, not theoretical.
  Diagnostic,  ///< Logging and triage; normally a session override, not saved.
};

struct Knob {
  std::string_view Key;
  std::string_view Label;
  std::string_view Summary;
  KnobKind Kind {KnobKind::Toggle};
  KnobGroup Group {KnobGroup::Performance};
  /// The value written when a Toggle is switched on, or the default for Integer.
  std::string_view OnValue {"1"};
  std::span<const std::string_view> Values; ///< Choice only.

  /**
   * True when the emulator tests only whether the variable is *present*.
   *
   * This matters and is easy to get wrong: for these, writing "0" turns the
   * feature ON just as "1" does. The only way to disable one is to remove the
   * key, so any UI that toggles it must erase rather than set a falsey value.
   */
  bool PresenceTested {false};
};

std::span<const Knob> Knobs();
const Knob* FindKnob(std::string_view Key);

/// Sets or erases a knob correctly, honouring PresenceTested.
void SetKnob(std::map<std::string, std::string>& Fex, const Knob& K, bool On, std::string_view Value = {});
bool KnobIsOn(const std::map<std::string, std::string>& Fex, const Knob& K);

/// Keys the SMC recipes own, so a recipe change can clear the previous one.
std::span<const std::string_view> SMCKeys();

} // namespace FastPPCx86::Launcher::Recipes
