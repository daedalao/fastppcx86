// SPDX-License-Identifier: MIT
#pragma once

#include "Session.h"

#include <QDialog>

class QLabel;
class QListWidget;
class QTabWidget;

namespace FastPPCx86::Launcher {

/**
 * The runtime-location manager: one tab per category.
 *
 * Every category is a list the user owns. Discovery seeds it and a rescan adds
 * to it, but nothing here is ever removed or rewritten behind their back, and
 * an entry that does not validate says why rather than just failing later.
 */
class PathsDialog final : public QDialog {
  Q_OBJECT

public:
  PathsDialog(Session& Sess, QWidget* Parent = nullptr);

private slots:
  void OnAdd();
  void OnEdit();
  void OnRemove();
  void OnToggleEnabled();
  void OnSetDefault();
  void OnRescan();
  void OnCategoryChanged();
  void OnSelectionChanged();

private:
  void Refresh();
  RuntimeCategory Category() const;
  RuntimeEntry* Selected();

  Session& Sess;
  QTabWidget* Tabs {};
  QListWidget* Lists[RuntimeCategoryCount] {};
  QLabel* Detail {};
};

} // namespace FastPPCx86::Launcher
