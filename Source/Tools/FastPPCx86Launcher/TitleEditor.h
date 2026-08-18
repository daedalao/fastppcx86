// SPDX-License-Identifier: MIT
#pragma once

#include "Registry.h"

#include <QDialog>

class QComboBox;
class QLineEdit;
class QPlainTextEdit;
class QSpinBox;

namespace FastPPCx86::Launcher {

/// Edits a title's identity: what to run, where, and with what arguments.
/// Tuning and runtime selection live in the main window, not here.
class TitleEditor final : public QDialog {
  Q_OBJECT

public:
  TitleEditor(Title& T, QWidget* Parent = nullptr);

private slots:
  void OnBrowse();
  void OnAccept();

private:
  Title& Edited;

  QLineEdit* Name {};
  QComboBox* Kind {};
  QLineEdit* Exe {};
  QLineEdit* WorkDir {};
  QLineEdit* Args {};
  QLineEdit* Prefix {};
  QSpinBox* Timeout {};
  QPlainTextEdit* Env {};
};

} // namespace FastPPCx86::Launcher
