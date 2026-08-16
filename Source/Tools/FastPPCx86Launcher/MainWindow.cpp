// SPDX-License-Identifier: MIT
#include "MainWindow.h"
#include "Discovery.h"

#include <Common/Config.h>
#include "PathsDialog.h"
#include "ProcessProbe.h"
#include "Recipes.h"
#include "Runtimes.h"
#include "ScanDialog.h"
#include "TitleEditor.h"

#include <QAction>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDesktopServices>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QFontDatabase>
#include <QRadioButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTimer>
#include <QToolBar>
#include <QUrl>
#include <QVBoxLayout>

#include <fmt/format.h>

#include <unistd.h>

#include <filesystem>

namespace FastPPCx86::Launcher {

namespace {
  QString Q(const std::string& Text) {
    return QString::fromStdString(Text);
  }

  QString Q(std::string_view Text) {
    return QString::fromUtf8(Text.data(), static_cast<int>(Text.size()));
  }
} // namespace

struct MainWindow::Widgets {
  QListWidget* TitleList {};
  QTabWidget* Tabs {};
  QLabel* EmptyState {};
  QWidget* DetailArea {};

  // Launch tab
  QComboBox* RuntimePickers[RuntimeCategoryCount] {};
  QLabel* BuildInfo {};
  QComboBox* Render {};
  QComboBox* CageMode {};
  QSpinBox* CageCores {};
  QSpinBox* CageThreads {};
  QSpinBox* CageReserve {};
  QLineEdit* CageCustom {};
  QLabel* CageResult {};
  QLabel* DisplayInfo {};
  QLabel* Diagnostics {};
  QPushButton* LaunchButton {};

  // Tuning tab
  QComboBox* Recipe {};
  QLabel* RecipeHelp {};
  QWidget* KnobArea {};
  std::vector<std::pair<const Recipes::Knob*, QWidget*>> Knobs;

  // Command / Run / Verify / Notes
  QPlainTextEdit* Command {};
  QPlainTextEdit* Output {};
  QLabel* RunStatus {};
  QPushButton* StopButton {};
  QPlainTextEdit* Verify {};
  QPlainTextEdit* Notes {};
};

MainWindow::MainWindow()
  : W(std::make_unique<Widgets>()) {
  std::string Error;
  if (!Sess.Load(Error)) {
    QMessageBox::critical(this, tr("Could not start"), Q(Error));
  }

  BuildUI();
  RefreshTitleList();
  RefreshEmptyState();

  PollTimer = new QTimer(this);
  PollTimer->setInterval(60);
  connect(PollTimer, &QTimer::timeout, this, &MainWindow::OnPollRunner);

  if (Sess.WasFirstRun()) {
    statusBar()->showMessage(tr("First run: found %1 location(s) on this machine.").arg(Sess.LastReport().TotalAdded()));
  }
}

MainWindow::~MainWindow() = default;

Title* MainWindow::CurrentTitle() {
  const int Row = W->TitleList->currentRow();
  if (Row < 0 || Row >= static_cast<int>(Sess.Reg().Titles.size())) {
    return nullptr;
  }
  return &Sess.Reg().Titles[static_cast<size_t>(Row)];
}

void MainWindow::BuildUI() {
  setWindowTitle(tr("FastPPCx86 Launcher"));
  resize(1180, 760);

  auto* Bar = addToolBar(tr("Main"));
  Bar->setMovable(false);
  Bar->addAction(tr("Scan for games"), this, &MainWindow::OnScan);
  Bar->addAction(tr("Locations"), this, &MainWindow::OnManagePaths);
  Bar->addAction(tr("Rescan"), this, &MainWindow::OnRescan);
  Bar->addSeparator();
  Bar->addAction(tr("Edit title"), this, &MainWindow::OnEditTitle);
  Bar->addAction(tr("Remove title"), this, &MainWindow::OnRemoveTitle);

  auto* Splitter = new QSplitter(Qt::Horizontal, this);

  W->TitleList = new QListWidget(Splitter);
  W->TitleList->setMinimumWidth(240);
  connect(W->TitleList, &QListWidget::currentRowChanged, this, &MainWindow::OnTitleSelected);

  auto* Right = new QWidget(Splitter);
  auto* RightLayout = new QVBoxLayout(Right);
  RightLayout->setContentsMargins(0, 0, 0, 0);

  W->EmptyState = new QLabel(Right);
  W->EmptyState->setWordWrap(true);
  W->EmptyState->setAlignment(Qt::AlignTop);
  W->EmptyState->setTextFormat(Qt::RichText);
  W->EmptyState->setContentsMargins(18, 18, 18, 18);
  RightLayout->addWidget(W->EmptyState);

  W->Tabs = new QTabWidget(Right);
  W->Tabs->addTab(BuildLaunchTab(), tr("Launch"));
  W->Tabs->addTab(BuildTuningTab(), tr("Tuning"));
  W->Tabs->addTab(BuildCommandTab(), tr("Command"));
  W->Tabs->addTab(BuildRunTab(), tr("Run"));
  W->Tabs->addTab(BuildVerifyTab(), tr("Verify"));
  W->Tabs->addTab(BuildNotesTab(), tr("Notes"));
  RightLayout->addWidget(W->Tabs);
  W->DetailArea = W->Tabs;

  Splitter->addWidget(W->TitleList);
  Splitter->addWidget(Right);
  Splitter->setStretchFactor(1, 1);
  setCentralWidget(Splitter);
  statusBar();
}

QWidget* MainWindow::BuildLaunchTab() {
  auto* Page = new QWidget;
  auto* Layout = new QVBoxLayout(Page);

  auto* Stack = new QGroupBox(tr("Runtime stack"), Page);
  auto* StackForm = new QFormLayout(Stack);
  for (const auto Category : AllRuntimeCategories) {
    if (Category == RuntimeCategory::Libraries) {
      continue; // Not a per-title choice; the scanner walks every enabled root.
    }
    auto* Picker = new QComboBox(Stack);
    Picker->setProperty("category", static_cast<int>(Category));
    connect(Picker, &QComboBox::currentIndexChanged, this, &MainWindow::OnRuntimeChanged);
    W->RuntimePickers[static_cast<size_t>(Category)] = Picker;
    StackForm->addRow(Q(DisplayName(Category)), Picker);
  }
  W->BuildInfo = new QLabel(Stack);
  W->BuildInfo->setWordWrap(true);
  StackForm->addRow(QString {}, W->BuildInfo);
  Layout->addWidget(Stack);

  auto* Graphics = new QGroupBox(tr("Graphics and display"), Page);
  auto* GraphicsForm = new QFormLayout(Graphics);
  W->Render = new QComboBox(Graphics);
  W->Render->addItem(tr("Native (host GL stack)"), "native");
  W->Render->addItem(tr("Zink (GL on Vulkan)"), "zink");
  W->Render->addItem(tr("llvmpipe (software)"), "llvmpipe");
  connect(W->Render, &QComboBox::currentIndexChanged, this, &MainWindow::OnRenderChanged);
  GraphicsForm->addRow(tr("Renderer"), W->Render);
  W->DisplayInfo = new QLabel(Graphics);
  W->DisplayInfo->setWordWrap(true);
  GraphicsForm->addRow(tr("Display"), W->DisplayInfo);
  Layout->addWidget(Graphics);

  auto* Cage = new QGroupBox(tr("CPU cage"), Page);
  auto* CageForm = new QFormLayout(Cage);
  W->CageMode = new QComboBox(Cage);
  W->CageMode->addItem(tr("Automatic (derive from this machine)"), "auto");
  W->CageMode->addItem(tr("Custom CPU list"), "custom");
  W->CageMode->addItem(tr("None"), "none");
  connect(W->CageMode, &QComboBox::currentIndexChanged, this, &MainWindow::OnCageChanged);
  CageForm->addRow(tr("Mode"), W->CageMode);

  W->CageCores = new QSpinBox(Cage);
  W->CageCores->setRange(0, 512);
  W->CageCores->setSpecialValueText(tr("automatic"));
  connect(W->CageCores, &QSpinBox::valueChanged, this, &MainWindow::OnCageChanged);
  CageForm->addRow(tr("Cores"), W->CageCores);

  W->CageThreads = new QSpinBox(Cage);
  W->CageThreads->setRange(1, 8);
  connect(W->CageThreads, &QSpinBox::valueChanged, this, &MainWindow::OnCageChanged);
  CageForm->addRow(tr("Threads per core"), W->CageThreads);

  W->CageReserve = new QSpinBox(Cage);
  W->CageReserve->setRange(0, 64);
  W->CageReserve->setToolTip(tr("Cores left to the host for the compositor, streaming and interrupts."));
  connect(W->CageReserve, &QSpinBox::valueChanged, this, &MainWindow::OnCageChanged);
  CageForm->addRow(tr("Reserve for host"), W->CageReserve);

  W->CageCustom = new QLineEdit(Cage);
  W->CageCustom->setPlaceholderText(tr("e.g. 0-1,8-9,16-17"));
  connect(W->CageCustom, &QLineEdit::editingFinished, this, &MainWindow::OnCageChanged);
  CageForm->addRow(tr("Custom list"), W->CageCustom);

  W->CageResult = new QLabel(Cage);
  W->CageResult->setWordWrap(true);
  CageForm->addRow(tr("Result"), W->CageResult);
  Layout->addWidget(Cage);

  W->Diagnostics = new QLabel(Page);
  W->Diagnostics->setWordWrap(true);
  W->Diagnostics->setTextFormat(Qt::RichText);
  Layout->addWidget(W->Diagnostics);

  Layout->addStretch();

  W->LaunchButton = new QPushButton(tr("Launch"), Page);
  W->LaunchButton->setMinimumHeight(38);
  connect(W->LaunchButton, &QPushButton::clicked, this, &MainWindow::OnLaunch);
  Layout->addWidget(W->LaunchButton);

  auto* Scroll = new QScrollArea;
  Scroll->setWidgetResizable(true);
  Scroll->setWidget(Page);
  return Scroll;
}

QWidget* MainWindow::BuildTuningTab() {
  auto* Page = new QWidget;
  auto* Layout = new QVBoxLayout(Page);

  auto* SMCBox = new QGroupBox(tr("Self-modifying code"), Page);
  auto* SMCLayout = new QVBoxLayout(SMCBox);
  W->Recipe = new QComboBox(SMCBox);
  W->Recipe->addItem(tr("Unset (leave it to the config layers)"), "unset");
  for (const auto& R : Recipes::SMC()) {
    W->Recipe->addItem(Q(R.Name), Q(R.Id));
  }
  connect(W->Recipe, &QComboBox::currentIndexChanged, this, &MainWindow::OnRecipeChanged);
  SMCLayout->addWidget(W->Recipe);
  W->RecipeHelp = new QLabel(SMCBox);
  W->RecipeHelp->setWordWrap(true);
  SMCLayout->addWidget(W->RecipeHelp);
  Layout->addWidget(SMCBox);

  // One group per knob class. Keeping the unsound options behind their own
  // heading, with the measurements in the tooltip, is the difference between
  // offering a fast option and misleading someone into a wrong answer.
  struct Section {
    Recipes::KnobGroup Group;
    QString Title;
  };
  const Section Sections[] {
    {Recipes::KnobGroup::Performance, tr("Performance")},
    {Recipes::KnobGroup::Unsound, tr("Known-unsound - these make the emulator produce answers x86 forbids")},
    {Recipes::KnobGroup::Diagnostic, tr("Diagnostics and triage")},
  };

  for (const auto& Section : Sections) {
    auto* Box = new QGroupBox(Section.Title, Page);
    auto* Form = new QFormLayout(Box);
    for (const auto& K : Recipes::Knobs()) {
      if (K.Group != Section.Group) {
        continue;
      }
      const QString Help = Q(K.Summary);
      if (K.Kind == Recipes::KnobKind::Toggle) {
        auto* Check = new QCheckBox(Q(K.Label), Box);
        Check->setToolTip(Help);
        Check->setProperty("knob", Q(K.Key));
        connect(Check, &QCheckBox::toggled, this, &MainWindow::OnKnobChanged);
        Form->addRow(Check);
        W->Knobs.emplace_back(&K, Check);
      } else if (K.Kind == Recipes::KnobKind::Integer) {
        auto* Edit = new QLineEdit(Box);
        Edit->setPlaceholderText(tr("off"));
        Edit->setToolTip(Help);
        Edit->setProperty("knob", Q(K.Key));
        connect(Edit, &QLineEdit::editingFinished, this, &MainWindow::OnKnobChanged);
        Form->addRow(Q(K.Label), Edit);
        W->Knobs.emplace_back(&K, Edit);
      } else {
        auto* Combo = new QComboBox(Box);
        Combo->setToolTip(Help);
        Combo->setProperty("knob", Q(K.Key));
        Combo->addItem(tr("unset"), QString {});
        for (const auto& V : K.Values) {
          Combo->addItem(Q(V), Q(V));
        }
        if (K.Values.empty()) {
          Combo->addItem(Q(K.OnValue), Q(K.OnValue));
        }
        connect(Combo, &QComboBox::currentIndexChanged, this, &MainWindow::OnKnobChanged);
        Form->addRow(Q(K.Label), Combo);
        W->Knobs.emplace_back(&K, Combo);
      }

      if (K.PresenceTested) {
        auto* Note = new QLabel(tr("Presence-tested: setting it to 0 enables it, so switching it off removes it."), Box);
        Note->setWordWrap(true);
        Form->addRow(QString {}, Note);
      }
    }
    Layout->addWidget(Box);
  }

  Layout->addStretch();

  auto* Scroll = new QScrollArea;
  Scroll->setWidgetResizable(true);
  Scroll->setWidget(Page);
  return Scroll;
}

QWidget* MainWindow::BuildCommandTab() {
  auto* Page = new QWidget;
  auto* Layout = new QVBoxLayout(Page);

  auto* Note = new QLabel(tr("This is exactly what a launch runs. It is generated from the same command the launcher "
                             "executes, so it cannot describe a different one. Copy it to reproduce a run in a "
                             "terminal or to attach to a bug report."),
                          Page);
  Note->setWordWrap(true);
  Layout->addWidget(Note);

  W->Command = new QPlainTextEdit(Page);
  W->Command->setReadOnly(true);
  W->Command->setLineWrapMode(QPlainTextEdit::NoWrap);
  W->Command->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
  Layout->addWidget(W->Command);

  return Page;
}

QWidget* MainWindow::BuildRunTab() {
  auto* Page = new QWidget;
  auto* Layout = new QVBoxLayout(Page);

  auto* Row = new QHBoxLayout;
  W->RunStatus = new QLabel(tr("Not running."), Page);
  W->RunStatus->setWordWrap(true);
  Row->addWidget(W->RunStatus, 1);

  W->StopButton = new QPushButton(tr("Stop"), Page);
  W->StopButton->setEnabled(false);
  connect(W->StopButton, &QPushButton::clicked, this, &MainWindow::OnStop);
  Row->addWidget(W->StopButton);

  auto* OpenLog = new QPushButton(tr("Open log"), Page);
  connect(OpenLog, &QPushButton::clicked, this, &MainWindow::OnOpenLog);
  Row->addWidget(OpenLog);

  // Unity redirects stdout and stderr into its own log, so the emulator's
  // diagnostics after the player starts do not appear here at all.
  auto* PlayerLog = new QPushButton(tr("Open Unity Player.log"), Page);
  PlayerLog->setToolTip(tr("Unity titles swallow stdout into their own log. Anything the emulator prints "
                           "after the player starts is in there, not in this pane."));
  connect(PlayerLog, &QPushButton::clicked, this, &MainWindow::OnOpenPlayerLog);
  Row->addWidget(PlayerLog);

  Layout->addLayout(Row);

  W->Output = new QPlainTextEdit(Page);
  W->Output->setReadOnly(true);
  W->Output->setMaximumBlockCount(20000);
  W->Output->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
  Layout->addWidget(W->Output);

  return Page;
}

QWidget* MainWindow::BuildVerifyTab() {
  auto* Page = new QWidget;
  auto* Layout = new QVBoxLayout(Page);

  auto* Note = new QLabel(tr("While a title is running this reads the FEX_* environment back off the live process "
                             "and compares it with what the launcher asked for. Config layers, AppConfig files and "
                             "stale exports all sit between an intended setting and the process, and an export that "
                             "did not arrive looks exactly like a setting that did nothing."),
                          Page);
  Note->setWordWrap(true);
  Layout->addWidget(Note);

  W->Verify = new QPlainTextEdit(Page);
  W->Verify->setReadOnly(true);
  W->Verify->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
  Layout->addWidget(W->Verify);

  return Page;
}

QWidget* MainWindow::BuildNotesTab() {
  auto* Page = new QWidget;
  auto* Layout = new QVBoxLayout(Page);
  W->Notes = new QPlainTextEdit(Page);
  W->Notes->setPlaceholderText(tr("Anything worth remembering about this title."));
  connect(W->Notes, &QPlainTextEdit::textChanged, this, [this] {
    if (Loading) {
      return;
    }
    if (Title* T = CurrentTitle()) {
      T->Notes = W->Notes->toPlainText().toStdString();
    }
  });
  Layout->addWidget(W->Notes);
  return Page;
}

void MainWindow::RefreshEmptyState() {
  const bool Empty = Sess.Reg().Titles.empty();
  W->DetailArea->setVisible(!Empty);
  W->EmptyState->setVisible(Empty);

  if (!Empty) {
    return;
  }

  QString Found;
  for (const auto Category : AllRuntimeCategories) {
    Found += QStringLiteral("<tr><td>%1</td><td>&nbsp;&nbsp;%2</td></tr>").arg(Q(DisplayName(Category)), Q(Sess.SummariseCategory(Category)));
  }

  W->EmptyState->setText(tr("<h2>No titles yet</h2>"
                            "<p>This launcher runs x86 games on POWER through FastPPCx86. Nothing here is hardcoded: "
                            "it looks for what you already have installed, and lets you add anything it missed.</p>"
                            "<h3>What was found on this machine</h3><table>%1</table>"
                            "<p><b>Scan for games</b> to find installed titles, or <b>Locations</b> to point it at "
                            "game libraries, emulator builds, RootFS images, Proton, Wine, DXVK and VKD3D.</p>")
                           .arg(Found));
}

void MainWindow::RefreshTitleList() {
  const int Previous = W->TitleList->currentRow();
  W->TitleList->clear();
  for (const auto& T : Sess.Reg().Titles) {
    const bool Present = T.Kind == TitleKind::Steam || Runtimes::IsRegularFile(ExpandPath(T.Exe));
    auto* Item = new QListWidgetItem(Q(fmt::format("{}   [{}]", T.Name.empty() ? T.Id : T.Name, ToString(T.Kind))));
    if (!Present) {
      Item->setToolTip(tr("The executable for this title is missing."));
      Item->setForeground(Qt::red);
    }
    W->TitleList->addItem(Item);
  }
  if (!Sess.Reg().Titles.empty()) {
    W->TitleList->setCurrentRow(std::clamp(Previous, 0, static_cast<int>(Sess.Reg().Titles.size()) - 1));
  }
  RefreshEmptyState();
}

void MainWindow::OnTitleSelected() {
  RefreshDetail();
}

void MainWindow::RefreshDetail() {
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }

  Loading = true;

  for (const auto Category : AllRuntimeCategories) {
    QComboBox* Picker = W->RuntimePickers[static_cast<size_t>(Category)];
    if (!Picker) {
      continue;
    }
    Picker->clear();
    Picker->addItem(tr("(inherit the default)"), QString {});
    for (const auto& Entry : Sess.Reg().List(Category)) {
      if (!Entry.Enabled) {
        continue;
      }
      const auto Result = Runtimes::Validate(Category, Entry);
      Picker->addItem(Q(Result.Ok ? Entry.Name : Entry.Name + "  [" + Result.Reason + "]"), Q(Entry.Id));
    }
    const int Index = Picker->findData(Q(T->Use.For(Category)));
    Picker->setCurrentIndex(Index >= 0 ? Index : 0);

    const bool Relevant = !((Category == RuntimeCategory::Proton && T->Kind != TitleKind::Proton) ||
                            (Category == RuntimeCategory::Wine && T->Kind != TitleKind::Wine));
    Picker->setEnabled(Relevant);
  }

  if (const RuntimeEntry* Build = Sess.Reg().Resolve(RuntimeCategory::EmulatorBuilds, *T)) {
    if (const auto Paths = Runtimes::ResolveEmulator(*Build)) {
      // Both binaries, always shown together: pointing FEX_BIN at a new build
      // while FEXBASH still names the old one runs a whole session on the wrong
      // binary and reports nothing.
      W->BuildInfo->setText(
        tr("FEX: %1\nFEXBash: %2\nBuilt: %3").arg(Q(Paths->FEX), Q(Paths->FEXBash), Q(Runtimes::DescribeModificationTime(Paths->FEX))));
    }
  } else {
    W->BuildInfo->setText(tr("No emulator build configured. Add one under Locations."));
  }

  W->Render->setCurrentIndex(W->Render->findData(Q(ToString(T->Render))));

  const char* ModeNames[] {"auto", "custom", "none"};
  W->CageMode->setCurrentIndex(W->CageMode->findData(QString::fromLatin1(ModeNames[static_cast<size_t>(T->Cage.Mode)])));
  W->CageCores->setValue(T->Cage.Cores);
  W->CageThreads->setValue(std::max(1, T->Cage.ThreadsPerCore));
  W->CageReserve->setValue(T->Cage.Reserve);
  W->CageCustom->setText(Q(T->Cage.CustomList));

  const auto Recipe = Recipes::ClassifySMC(T->Fex);
  int RecipeIndex = W->Recipe->findData(Q(Recipe));
  if (RecipeIndex < 0) {
    if (W->Recipe->findData(QStringLiteral("custom")) < 0) {
      W->Recipe->addItem(tr("Custom (edited by hand)"), QStringLiteral("custom"));
    }
    RecipeIndex = W->Recipe->findData(QStringLiteral("custom"));
  }
  W->Recipe->setCurrentIndex(RecipeIndex);
  if (const auto* R = Recipes::FindSMC(Recipe)) {
    W->RecipeHelp->setText(Q(R->Summary));
  } else {
    W->RecipeHelp->setText(tr("No SMC options are set, so the config layers below decide."));
  }

  for (const auto& [Knob, Widget] : W->Knobs) {
    const bool On = Recipes::KnobIsOn(T->Fex, *Knob);
    const auto Found = T->Fex.find(std::string {Knob->Key});
    const QString Value = Found == T->Fex.end() ? QString {} : Q(Found->second);

    if (auto* Check = qobject_cast<QCheckBox*>(Widget)) {
      Check->setChecked(On);
    } else if (auto* Edit = qobject_cast<QLineEdit*>(Widget)) {
      Edit->setText(On ? Value : QString {});
    } else if (auto* Combo = qobject_cast<QComboBox*>(Widget)) {
      const int Index = On ? Combo->findData(Value) : 0;
      Combo->setCurrentIndex(Index >= 0 ? Index : 0);
    }
  }

  W->Notes->setPlainText(Q(T->Notes));

  Loading = false;

  RefreshCommand();
}

void MainWindow::RefreshCommand() {
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }

  const auto Spec = Build(Sess.Reg(), *T);

  W->Command->setPlainText(Q(Spec.ShellCommand()));
  W->CageResult->setText(Q(Spec.CageExplanation));

  const auto Env = HostEnv::Environment::FromCurrent();
  const auto Display = HostEnv::ResolveDisplay(Env);
  W->DisplayInfo->setText(
    Display.Problem.empty() ?
      tr("%1 (%2), xauth %3").arg(Q(Display.Display), Q(Display.Source), Display.XAuthority.empty() ? tr("none needed") : Q(Display.XAuthority)) :
      Q(Display.Problem));

  QString Notes;
  for (const auto& D : Spec.Diagnostics) {
    const char* Colour = D.Severity == Diagnostic::Level::Error   ? "#c0392b" :
                         D.Severity == Diagnostic::Level::Warning ? "#b9770e" :
                                                                    "#555555";
    Notes += QStringLiteral("<p style='color:%1;margin:2px 0'>%2</p>").arg(QString::fromLatin1(Colour), Q(D.Text).toHtmlEscaped());
  }
  W->Diagnostics->setText(Notes);
  W->LaunchButton->setEnabled(Spec.Ok && !Run);
}

void MainWindow::OnRuntimeChanged() {
  if (Loading) {
    return;
  }
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }
  for (const auto Category : AllRuntimeCategories) {
    if (QComboBox* Picker = W->RuntimePickers[static_cast<size_t>(Category)]) {
      T->Use.For(Category) = Picker->currentData().toString().toStdString();
    }
  }
  SaveRegistry();
  RefreshCommand();
}

void MainWindow::OnRenderChanged() {
  if (Loading) {
    return;
  }
  if (Title* T = CurrentTitle()) {
    T->Render = RenderBackendFromString(W->Render->currentData().toString().toStdString()).value_or(RenderBackend::Native);
    SaveRegistry();
    RefreshCommand();
  }
}

void MainWindow::OnCageChanged() {
  if (Loading) {
    return;
  }
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }
  const auto Mode = W->CageMode->currentData().toString();
  T->Cage.Mode = Mode == "custom" ? Topology::CageMode::Custom : Mode == "none" ? Topology::CageMode::None : Topology::CageMode::Auto;
  T->Cage.Cores = W->CageCores->value();
  T->Cage.ThreadsPerCore = W->CageThreads->value();
  T->Cage.Reserve = W->CageReserve->value();
  T->Cage.CustomList = W->CageCustom->text().toStdString();

  const bool Custom = T->Cage.Mode == Topology::CageMode::Custom;
  const bool Auto = T->Cage.Mode == Topology::CageMode::Auto;
  W->CageCustom->setEnabled(Custom);
  W->CageCores->setEnabled(Auto);
  W->CageThreads->setEnabled(Auto);
  W->CageReserve->setEnabled(Auto);

  SaveRegistry();
  RefreshCommand();
}

void MainWindow::OnRecipeChanged() {
  if (Loading) {
    return;
  }
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }

  const auto Id = W->Recipe->currentData().toString().toStdString();
  if (Id == "custom") {
    return;
  }

  if (const auto* R = Recipes::FindSMC(Id); R && R->Risky) {
    const auto Answer = QMessageBox::question(this, tr("Are you sure?"), Q(R->Summary), QMessageBox::Yes | QMessageBox::No);
    if (Answer != QMessageBox::Yes) {
      RefreshDetail();
      return;
    }
  }

  Recipes::ApplySMC(T->Fex, Id);
  SaveRegistry();
  RefreshDetail();
}

void MainWindow::OnKnobChanged() {
  if (Loading) {
    return;
  }
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }

  auto* Source = sender();
  for (const auto& [Knob, Widget] : W->Knobs) {
    if (Widget != Source) {
      continue;
    }

    if (auto* Check = qobject_cast<QCheckBox*>(Widget)) {
      if (Check->isChecked() && Knob->Group == Recipes::KnobGroup::Unsound) {
        const auto Answer = QMessageBox::warning(this, tr("This option is unsound"), Q(Knob->Summary), QMessageBox::Yes | QMessageBox::No);
        if (Answer != QMessageBox::Yes) {
          Check->setChecked(false);
          return;
        }
      }
      Recipes::SetKnob(T->Fex, *Knob, Check->isChecked());
    } else if (auto* Edit = qobject_cast<QLineEdit*>(Widget)) {
      const auto Text = Edit->text().trimmed();
      Recipes::SetKnob(T->Fex, *Knob, !Text.isEmpty(), Text.toStdString());
    } else if (auto* Combo = qobject_cast<QComboBox*>(Widget)) {
      const auto Value = Combo->currentData().toString();
      Recipes::SetKnob(T->Fex, *Knob, !Value.isEmpty(), Value.toStdString());
    }
    break;
  }

  SaveRegistry();
  RefreshCommand();
}

void MainWindow::OnLaunch() {
  Title* T = CurrentTitle();
  if (!T || Run) {
    return;
  }

  // Side effects first (installing a selected DXVK/VKD3D into the prefix), then
  // build, so the command picks up any WINEDLLOVERRIDES that produced. Build
  // itself stays pure, which is what lets the Command tab refresh on every
  // keystroke without touching the disk.
  const auto Prepared = Prepare(Sess.Reg(), *T);

  ActiveSpec = Build(Sess.Reg(), *T);
  if (!ActiveSpec.Ok) {
    QString Text;
    for (const auto& D : ActiveSpec.Diagnostics) {
      if (D.Severity == Diagnostic::Level::Error) {
        Text += Q(D.Text) + "\n\n";
      }
    }
    QMessageBox::warning(this, tr("Cannot launch"), Text);
    return;
  }

  Run = std::make_unique<Runner>();
  std::string Error;
  if (!Run->Start(ActiveSpec, Error)) {
    Run.reset();
    QMessageBox::critical(this, tr("Launch failed"), Q(Error));
    return;
  }

  W->Output->clear();
  for (const auto& D : Prepared.Diagnostics) {
    W->Output->appendPlainText(QStringLiteral("== ") + Q(D.Text));
  }
  W->Verify->clear();
  W->RunStatus->setText(tr("Running (pid %1). Log: %2").arg(Run->Pid()).arg(Q(ActiveSpec.LogPath)));
  W->StopButton->setEnabled(true);
  W->LaunchButton->setEnabled(false);
  W->Tabs->setCurrentIndex(3);
  PollTimer->start();
}

void MainWindow::OnStop() {
  if (Run) {
    Run->RequestStop();
    W->RunStatus->setText(tr("Asked the title to stop..."));
  }
}

void MainWindow::closeEvent(QCloseEvent* Event) {
  if (Run && Run->Running()) {
    const auto Choice = QMessageBox::question(this, tr("A title is still running"),
                                              tr("Quitting now would leave the title writing into a closed pipe, and its next line of "
                                                 "output would kill it with SIGPIPE at some arbitrary later moment.\n\n"
                                                 "Stop the title (and everything it spawned) and quit?"),
                                              QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
    if (Choice != QMessageBox::Yes) {
      Event->ignore();
      return;
    }
    // Bounded synchronous wind-down: SIGTERM the group, give it three seconds
    // to exit, then SIGKILL. Poll() keeps draining output into the log so the
    // shutdown lines are captured.
    Run->RequestStop();
    for (int I = 0; I < 30 && Run->Running(); ++I) {
      Run->Poll(nullptr);
      ::usleep(100 * 1000);
    }
    if (Run->Running()) {
      Run->Kill();
      for (int I = 0; I < 20 && Run->Running(); ++I) {
        Run->Poll(nullptr);
        ::usleep(100 * 1000);
      }
    }
  }
  QMainWindow::closeEvent(Event);
}

void MainWindow::OnPollRunner() {
  if (!Run) {
    PollTimer->stop();
    return;
  }

  QString Chunk;
  const bool Active = Run->Poll([&Chunk](std::string_view Data) { Chunk += QString::fromUtf8(Data.data(), static_cast<int>(Data.size())); });
  if (!Chunk.isEmpty()) {
    // Trailing newlines would otherwise double-space the pane, since
    // appendPlainText adds its own paragraph break.
    while (Chunk.endsWith(QLatin1Char('\n'))) {
      Chunk.chop(1);
    }
    W->Output->appendPlainText(Chunk);
  }

  RefreshVerify();

  if (!Active) {
    PollTimer->stop();
    W->RunStatus->setText(tr("%1. Log: %2").arg(Q(Run->ExitSummary()), Q(ActiveSpec.LogPath)));
    W->StopButton->setEnabled(false);
    Run.reset();
    W->LaunchButton->setEnabled(true);
  }
}

void MainWindow::RefreshVerify() {
  if (!Run) {
    return;
  }

  const auto Guest = ProcessProbe::FindGuest(Run->Pid());
  if (!Guest) {
    W->Verify->setPlainText(tr("No emulator process found under this run yet."));
    return;
  }

  QString Text = Q(fmt::format("pid {}\n{}\n\n", Guest->Pid, Guest->Exe));
  if (Guest->ExeDeleted) {
    Text += tr("WARNING: this process's binary has been deleted or replaced since it started.\n"
               "It is running a build that no longer exists on disk. Rebuilding under a running\n"
               "title does this, and any A/B you are measuring is against the old binary.\n\n");
  }

  const auto Comparison = ProcessProbe::Compare(ActiveSpec.FexVars(), Guest->FexVars);
  if (Comparison.Matches()) {
    Text += tr("Every FEX_* variable matches what the launcher set.\n\n");
  }
  for (const auto& D : Comparison.Differences) {
    Text += Q(D.Missing ? fmt::format("MISSING  {} (expected {})\n", D.Key, D.Expected) :
                          fmt::format("DIFFERS  {}: expected {}, process has {}\n", D.Key, D.Expected, D.Actual));
  }
  for (const auto& Key : Comparison.Unexpected) {
    Text += Q(fmt::format("EXTRA    {}={}  (from a config layer or a stale export)\n", Key, Guest->FexVars.at(Key)));
  }

  Text += tr("\nEnvironment of the running process:\n");
  for (const auto& [Key, Value] : Guest->FexVars) {
    Text += Q(fmt::format("  {}={}\n", Key, Value));
  }

  // Preserve the scroll position: this refreshes every poll tick and yanking the
  // view back to the top while someone is reading it is maddening.
  const int Scroll = W->Verify->verticalScrollBar()->value();
  W->Verify->setPlainText(Text);
  W->Verify->verticalScrollBar()->setValue(Scroll);
}

void MainWindow::OnOpenLog() {
  if (!ActiveSpec.LogPath.empty()) {
    QDesktopServices::openUrl(QUrl::fromLocalFile(Q(ActiveSpec.LogPath)));
  }
}

void MainWindow::OnOpenPlayerLog() {
  const auto Home = std::string {FEX::Config::GetHomeDirectory().c_str()};
  const auto Root = Home + "/.config/unity3d";
  if (!Runtimes::IsDirectory(Root)) {
    QMessageBox::information(this, tr("Player.log"),
                             tr("No Unity logs found under %1. Unity only creates this once a Unity title has run.").arg(Q(Root)));
    return;
  }
  QDesktopServices::openUrl(QUrl::fromLocalFile(Q(Root)));
}

void MainWindow::OnRescan() {
  const auto Report = Sess.Rescan();
  SaveRegistry();
  RefreshDetail();
  statusBar()->showMessage(Report.TotalAdded() > 0 ?
                             tr("Rescan added %1 new location(s). Your own entries were left alone.").arg(Report.TotalAdded()) :
                             tr("Rescan found nothing new."),
                           6000);
}

void MainWindow::OnScan() {
  ScanDialog Dialog(Sess, this);
  if (Dialog.exec() == QDialog::Accepted && Dialog.AddedAny()) {
    SaveRegistry();
    RefreshTitleList();
    W->TitleList->setCurrentRow(static_cast<int>(Sess.Reg().Titles.size()) - 1);
  }
}

void MainWindow::OnManagePaths() {
  PathsDialog Dialog(Sess, this);
  Dialog.exec();
  SaveRegistry();
  RefreshDetail();
  RefreshEmptyState();
}

void MainWindow::OnEditTitle() {
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }
  TitleEditor Editor(*T, this);
  if (Editor.exec() == QDialog::Accepted) {
    SaveRegistry();
    RefreshTitleList();
    RefreshDetail();
  }
}

void MainWindow::OnRemoveTitle() {
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }
  const auto Answer =
    QMessageBox::question(this, tr("Remove title"), tr("Remove '%1' from the launcher? The game itself is not touched.").arg(Q(T->Name)),
                          QMessageBox::Yes | QMessageBox::No);
  if (Answer != QMessageBox::Yes) {
    return;
  }
  Sess.Reg().Titles.erase(Sess.Reg().Titles.begin() + W->TitleList->currentRow());
  SaveRegistry();
  RefreshTitleList();
}

void MainWindow::SaveRegistry() {
  std::string Error;
  if (!Sess.Save(Error)) {
    statusBar()->showMessage(tr("Could not save: %1").arg(Q(Error)), 8000);
  }
}

} // namespace FastPPCx86::Launcher
