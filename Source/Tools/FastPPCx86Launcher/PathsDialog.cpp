// SPDX-License-Identifier: MIT
#include "PathsDialog.h"
#include "Runtimes.h"

#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QTabWidget>
#include <QVBoxLayout>

#include <fmt/format.h>

#include <filesystem>

namespace FastPPCx86::Launcher {

namespace {
  QString Q(const std::string& Text) {
    return QString::fromStdString(Text);
  }

  QString Q(std::string_view Text) {
    return QString::fromUtf8(Text.data(), static_cast<int>(Text.size()));
  }

  /// What each category needs, shown above its list so the user knows what a
  /// valid entry looks like before they go hunting for one.
  QString Explain(RuntimeCategory Category) {
    switch (Category) {
    case RuntimeCategory::Libraries:
      return QObject::tr("Directories holding installed games. The scanner walks every enabled entry. "
                         "Steam libraries on other drives are read from libraryfolders.vdf.");
    case RuntimeCategory::EmulatorBuilds:
      return QObject::tr("Directories containing both FEX and FEXBash. Both come from the same entry on purpose: "
                         "pointing one at a new build while the other still names the old one runs a whole session "
                         "on the wrong binary without saying so.");
    case RuntimeCategory::RootFS:
      return QObject::tr("x86-64 root filesystems. A directory, or a squashfs/EROFS image. Everything the guest "
                         "links against comes from here. FEXRootFSFetcher downloads one.");
    case RuntimeCategory::ThunkSets:
      return QObject::tr("Host and guest thunk library pairs, which route guest GL and Vulkan to the host's own "
                         "drivers. The two halves are one entry because a mismatched pair fails at the call "
                         "boundary, a long way from anything that points at the cause.");
    case RuntimeCategory::Proton: return QObject::tr("Proton trees, for Windows titles. Any directory containing a 'proton' script.");
    case RuntimeCategory::Wine: return QObject::tr("Wine trees, for Windows titles without Proton. Any directory containing bin/wine64.");
    case RuntimeCategory::DXVK:
      return QObject::tr("DXVK builds. Selecting one installs its DLLs into a title's prefix and overrides the "
                         "copy Proton bundles. Needs x64/d3d11.dll.");
    case RuntimeCategory::VKD3D: return QObject::tr("VKD3D-Proton builds, for D3D12 titles. Needs x64/d3d12.dll and d3d12core.dll.");
    }
    return {};
  }
} // namespace

PathsDialog::PathsDialog(Session& S, QWidget* Parent)
  : QDialog(Parent)
  , Sess(S) {
  setWindowTitle(tr("Locations"));
  resize(940, 620);

  auto* Layout = new QVBoxLayout(this);

  Tabs = new QTabWidget(this);
  for (const auto Category : AllRuntimeCategories) {
    auto* Page = new QWidget(Tabs);
    auto* PageLayout = new QVBoxLayout(Page);

    auto* Help = new QLabel(Explain(Category), Page);
    Help->setWordWrap(true);
    PageLayout->addWidget(Help);

    auto* List = new QListWidget(Page);
    connect(List, &QListWidget::currentRowChanged, this, &PathsDialog::OnSelectionChanged);
    PageLayout->addWidget(List);
    Lists[static_cast<size_t>(Category)] = List;

    Tabs->addTab(Page, Q(DisplayName(Category)));
  }
  connect(Tabs, &QTabWidget::currentChanged, this, &PathsDialog::OnCategoryChanged);
  Layout->addWidget(Tabs);

  Detail = new QLabel(this);
  Detail->setWordWrap(true);
  Detail->setTextFormat(Qt::RichText);
  Detail->setMinimumHeight(48);
  Layout->addWidget(Detail);

  auto* Buttons = new QHBoxLayout;
  const struct {
    QString Text;
    void (PathsDialog::*Slot)();
    QString Tip;
  } Actions[] {
    {tr("Add..."), &PathsDialog::OnAdd, {}},
    {tr("Edit..."), &PathsDialog::OnEdit, {}},
    {tr("Remove"), &PathsDialog::OnRemove, tr("Forgets the location. Nothing on disk is touched.")},
    {tr("Enable/disable"), &PathsDialog::OnToggleEnabled, {}},
    {tr("Set as default"), &PathsDialog::OnSetDefault, tr("Used by titles that do not choose one themselves.")},
    {tr("Rescan"), &PathsDialog::OnRescan, tr("Adds newly-found locations. Never removes yours.")},
  };
  for (const auto& Action : Actions) {
    auto* Button = new QPushButton(Action.Text, this);
    if (!Action.Tip.isEmpty()) {
      Button->setToolTip(Action.Tip);
    }
    connect(Button, &QPushButton::clicked, this, Action.Slot);
    Buttons->addWidget(Button);
  }
  Buttons->addStretch();

  auto* Close = new QPushButton(tr("Close"), this);
  connect(Close, &QPushButton::clicked, this, &QDialog::accept);
  Buttons->addWidget(Close);
  Layout->addLayout(Buttons);

  Refresh();
}

RuntimeCategory PathsDialog::Category() const {
  return AllRuntimeCategories[static_cast<size_t>(std::max(0, Tabs->currentIndex()))];
}

RuntimeEntry* PathsDialog::Selected() {
  const auto Cat = Category();
  auto& List = Sess.Reg().List(Cat);
  const int Row = Lists[static_cast<size_t>(Cat)]->currentRow();
  if (Row < 0 || Row >= static_cast<int>(List.size())) {
    return nullptr;
  }
  return &List[static_cast<size_t>(Row)];
}

void PathsDialog::Refresh() {
  for (const auto Cat : AllRuntimeCategories) {
    auto* List = Lists[static_cast<size_t>(Cat)];
    const int Previous = List->currentRow();
    List->clear();

    const auto& Entries = Sess.Reg().List(Cat);
    const auto& DefaultId = Sess.Reg().Defaults.For(Cat);

    for (const auto& Entry : Entries) {
      const auto Result = Runtimes::Validate(Cat, Entry);
      const bool IsDefault = !DefaultId.empty() && DefaultId == Entry.Id;

      std::string Location = Entry.Path;
      if (Cat == RuntimeCategory::ThunkSets) {
        Location = fmt::format("host={}  guest={}", Entry.HostLibs.empty() ? "(built-in)" : Entry.HostLibs,
                               Entry.GuestLibs.empty() ? "(built-in)" : Entry.GuestLibs);
      }

      auto* Item = new QListWidgetItem(Q(fmt::format("{}{}  -  {}", Entry.Name, IsDefault ? "  [default]" : "", Location)));
      if (!Entry.Enabled) {
        Item->setForeground(Qt::gray);
        Item->setToolTip(tr("Disabled."));
      } else if (!Result.Ok) {
        Item->setForeground(Qt::red);
        Item->setToolTip(Q(Result.Reason));
      } else if (!Result.Note.empty()) {
        Item->setToolTip(Q(Result.Note));
      }
      List->addItem(Item);
    }

    if (!Entries.empty()) {
      List->setCurrentRow(std::clamp(Previous, 0, static_cast<int>(Entries.size()) - 1));
    }
  }
  OnSelectionChanged();
}

void PathsDialog::OnCategoryChanged() {
  OnSelectionChanged();
}

void PathsDialog::OnSelectionChanged() {
  const auto Cat = Category();
  const RuntimeEntry* Entry = const_cast<PathsDialog*>(this)->Selected();

  if (!Entry) {
    // An empty category names every directory that was searched, so the user
    // knows what to install or where to point it rather than guessing.
    const auto& Searched = Sess.LastReport().Searched[static_cast<size_t>(Cat)];
    QString Text = tr("<b>Nothing configured here.</b>");
    if (!Searched.empty()) {
      Text += tr("<br>Searched:<br>");
      for (const auto& Dir : Searched) {
        Text += Q(Dir).toHtmlEscaped() + "<br>";
      }
    }
    Detail->setText(Text);
    return;
  }

  const auto Result = Runtimes::Validate(Cat, *Entry);
  QString Text = QStringLiteral("<b>%1</b><br>%2")
                   .arg(Q(Entry->Name).toHtmlEscaped(),
                        Q(Cat == RuntimeCategory::ThunkSets ? Entry->HostLibs + " / " + Entry->GuestLibs : Entry->Path).toHtmlEscaped());
  if (!Result.Ok) {
    Text += QStringLiteral("<br><span style='color:#c0392b'>%1</span>").arg(Q(Result.Reason).toHtmlEscaped());
  } else if (!Result.Note.empty()) {
    Text += QStringLiteral("<br><span style='color:#b9770e'>%1</span>").arg(Q(Result.Note).toHtmlEscaped());
  }
  Detail->setText(Text);
}

void PathsDialog::OnAdd() {
  const auto Cat = Category();
  RuntimeEntry Entry;

  if (Cat == RuntimeCategory::ThunkSets) {
    const auto Host = QFileDialog::getExistingDirectory(this, tr("Host thunk directory"));
    const auto Guest = QFileDialog::getExistingDirectory(this, tr("Guest thunk directory"));
    if (Host.isEmpty() && Guest.isEmpty()) {
      return;
    }
    Entry.HostLibs = Host.toStdString();
    Entry.GuestLibs = Guest.toStdString();
    Entry.Name = tr("Custom thunks").toStdString();
  } else {
    const auto Path = QFileDialog::getExistingDirectory(this, tr("Choose a directory"));
    if (Path.isEmpty()) {
      return;
    }
    Entry.Path = Path.toStdString();
    Entry.Name = std::filesystem::path {Entry.Path}.filename().string();
  }

  bool Ok = false;
  const auto Name = QInputDialog::getText(this, tr("Name"), tr("A label for this entry:"), QLineEdit::Normal, Q(Entry.Name), &Ok);
  if (!Ok) {
    return;
  }
  Entry.Name = Name.toStdString();

  const auto Result = Runtimes::Validate(Cat, Entry);
  if (!Result.Ok) {
    const auto Answer = QMessageBox::question(this, tr("This does not look usable"), tr("%1\n\nAdd it anyway?").arg(Q(Result.Reason)),
                                              QMessageBox::Yes | QMessageBox::No);
    if (Answer != QMessageBox::Yes) {
      return;
    }
  }

  Sess.Reg().Add(Cat, std::move(Entry));
  Refresh();
}

void PathsDialog::OnEdit() {
  const auto Cat = Category();
  RuntimeEntry* Entry = Selected();
  if (!Entry) {
    return;
  }

  bool Ok = false;
  const auto Name = QInputDialog::getText(this, tr("Name"), tr("Label:"), QLineEdit::Normal, Q(Entry->Name), &Ok);
  if (Ok) {
    Entry->Name = Name.toStdString();
  }

  if (Cat == RuntimeCategory::ThunkSets) {
    const auto Host = QInputDialog::getText(this, tr("Host thunks"), tr("Host thunk directory:"), QLineEdit::Normal, Q(Entry->HostLibs), &Ok);
    if (Ok) {
      Entry->HostLibs = Host.toStdString();
    }
    const auto Guest = QInputDialog::getText(this, tr("Guest thunks"), tr("Guest stub directory:"), QLineEdit::Normal, Q(Entry->GuestLibs), &Ok);
    if (Ok) {
      Entry->GuestLibs = Guest.toStdString();
    }
  } else {
    const auto Path =
      QInputDialog::getText(this, tr("Path"), tr("Location. ~ and $VARS are kept as typed:"), QLineEdit::Normal, Q(Entry->Path), &Ok);
    if (Ok) {
      Entry->Path = Path.toStdString();
    }
  }

  // An edited entry belongs to the user now, so a later rescan will not treat it
  // as something discovery owns.
  Entry->Discovered = false;
  Refresh();
}

void PathsDialog::OnRemove() {
  const auto Cat = Category();
  RuntimeEntry* Entry = Selected();
  if (!Entry) {
    return;
  }

  const auto Answer = QMessageBox::question(this, tr("Remove entry"),
                                            tr("Remove '%1'? This only forgets the location; nothing on disk is touched.").arg(Q(Entry->Name)),
                                            QMessageBox::Yes | QMessageBox::No);
  if (Answer != QMessageBox::Yes) {
    return;
  }

  // Titles pointing at it fall back to the default rather than breaking.
  const auto RemovedId = Entry->Id;
  auto& List = Sess.Reg().List(Cat);
  List.erase(List.begin() + Lists[static_cast<size_t>(Cat)]->currentRow());
  for (auto& T : Sess.Reg().Titles) {
    if (T.Use.For(Cat) == RemovedId) {
      T.Use.For(Cat).clear();
    }
  }
  if (Sess.Reg().Defaults.For(Cat) == RemovedId) {
    Sess.Reg().Defaults.For(Cat).clear();
  }

  Refresh();
}

void PathsDialog::OnToggleEnabled() {
  if (RuntimeEntry* Entry = Selected()) {
    Entry->Enabled = !Entry->Enabled;
    Refresh();
  }
}

void PathsDialog::OnSetDefault() {
  if (RuntimeEntry* Entry = Selected()) {
    Sess.Reg().Defaults.For(Category()) = Entry->Id;
    Refresh();
  }
}

void PathsDialog::OnRescan() {
  const auto Report = Sess.Rescan();
  Refresh();
  QMessageBox::information(this, tr("Rescan"),
                           Report.TotalAdded() > 0 ? tr("Added %1 new location(s). Your own entries were left alone.").arg(Report.TotalAdded()) :
                                                     tr("Nothing new was found."));
}

} // namespace FastPPCx86::Launcher
