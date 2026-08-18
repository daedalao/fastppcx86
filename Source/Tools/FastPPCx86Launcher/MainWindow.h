// SPDX-License-Identifier: MIT
#pragma once

#include "LaunchSpec.h"
#include "Runner.h"
#include "Session.h"

#include <QMainWindow>
#include <memory>

class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QTabWidget;
class QTimer;
class QVBoxLayout;
class QWidget;

namespace FastPPCx86::Launcher {

/**
 * The graphical frontend.
 *
 * Qt Widgets rather than QtQuick on purpose: it needs no scene graph, so the
 * launcher does not compete for the GL/Vulkan stack the guest titles are using,
 * and it works over plain X11 and remote sessions. qt6-base is already a
 * dependency of the package, so this adds nothing new to install.
 */
class MainWindow final : public QMainWindow {
  Q_OBJECT

public:
  MainWindow();
  ~MainWindow() override;

protected:
  /// A running title's stdout/stderr feed through the Runner's pipe, so
  /// destroying the window mid-run would close the read end and the title's
  /// next write would take SIGPIPE -- a silent kill at an arbitrary later
  /// moment. Ask, and on "stop" bring the process group down cleanly first.
  void closeEvent(QCloseEvent* Event) override;

private slots:
  void OnTitleSelected();
  void OnLaunch();
  void OnStop();
  void OnRescan();
  void OnScan();
  void OnManagePaths();
  void OnEditTitle();
  void OnRemoveTitle();
  void OnPollRunner();
  void OnRuntimeChanged();
  void OnRecipeChanged();
  void OnKnobChanged();
  void OnRenderChanged();
  void OnCageChanged();
  void OnOpenLog();
  void OnOpenPlayerLog();

private:
  void BuildUI();
  QWidget* BuildLaunchTab();
  QWidget* BuildTuningTab();
  QWidget* BuildCommandTab();
  QWidget* BuildRunTab();
  QWidget* BuildVerifyTab();
  QWidget* BuildNotesTab();

  void RefreshTitleList();
  void RefreshDetail();
  void RefreshCommand();
  void RefreshVerify();
  void RefreshEmptyState();
  void SaveRegistry();

  Title* CurrentTitle();

  struct Widgets;
  std::unique_ptr<Widgets> W;

  Session Sess;
  std::unique_ptr<Runner> Run;
  QTimer* PollTimer {};
  LaunchSpec ActiveSpec;
  /// Set while a refresh is repopulating controls, so their change signals do
  /// not write the values back into the title they were just loaded from.
  bool Loading {false};
};

} // namespace FastPPCx86::Launcher
