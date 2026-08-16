// SPDX-License-Identifier: MIT
#pragma once

#include "Discovery.h"
#include "Hints.h"
#include "Session.h"

#include <QDialog>
#include <vector>

class QLabel;
class QTreeWidget;

namespace FastPPCx86::Launcher {

/// Walks the configured game libraries and offers what it found for import.
class ScanDialog final : public QDialog {
  Q_OBJECT

public:
  ScanDialog(Session& Sess, QWidget* Parent = nullptr);

  bool AddedAny() const {
    return Added;
  }

private slots:
  void OnImport();
  void OnSelectionChanged();

private:
  void Populate();

  Session& Sess;
  QTreeWidget* Tree {};
  QLabel* Detail {};
  std::vector<Discovery::Candidate> Candidates;
  std::vector<Hints::Hint> KnownHints;
  bool Added {false};
};

} // namespace FastPPCx86::Launcher
