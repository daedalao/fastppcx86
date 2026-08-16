// SPDX-License-Identifier: MIT
#include "ScanDialog.h"
#include "Recipes.h"

#include <QApplication>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <fmt/format.h>

#include <filesystem>

namespace FastPPCx86::Launcher {

namespace {
  QString Q(const std::string& Text) {
    return QString::fromStdString(Text);
  }

  QString Describe(Discovery::BinaryKind Kind) {
    switch (Kind) {
    case Discovery::BinaryKind::GuestELF64: return QObject::tr("x86-64 Linux");
    case Discovery::BinaryKind::GuestELF32: return QObject::tr("i386 Linux");
    case Discovery::BinaryKind::WindowsPE64: return QObject::tr("Windows 64-bit");
    case Discovery::BinaryKind::WindowsPE32: return QObject::tr("Windows 32-bit");
    case Discovery::BinaryKind::HostELF: return QObject::tr("host binary");
    case Discovery::BinaryKind::ForeignELF: return QObject::tr("other architecture");
    case Discovery::BinaryKind::Script: return QObject::tr("script");
    case Discovery::BinaryKind::Unknown: break;
    }
    return QObject::tr("unknown");
  }

  QString HumanSize(int64_t Bytes) {
    static const char* Units[] {"B", "KB", "MB", "GB"};
    double Value = static_cast<double>(Bytes);
    size_t Unit {};
    while (Value >= 1024.0 && Unit + 1 < std::size(Units)) {
      Value /= 1024.0;
      ++Unit;
    }
    return QStringLiteral("%1 %2").arg(Value, 0, 'f', Unit == 0 ? 0 : 1).arg(QString::fromLatin1(Units[Unit]));
  }
} // namespace

ScanDialog::ScanDialog(Session& S, QWidget* Parent)
  : QDialog(Parent)
  , Sess(S) {
  setWindowTitle(tr("Scan for games"));
  resize(1000, 640);

  auto* Layout = new QVBoxLayout(this);

  auto* Note = new QLabel(tr("Candidates found in your configured game libraries, grouped by install directory and "
                             "ranked so the main executable of each is first. Pick the ones you want and import them."),
                          this);
  Note->setWordWrap(true);
  Layout->addWidget(Note);

  Tree = new QTreeWidget(this);
  Tree->setColumnCount(4);
  Tree->setHeaderLabels({tr("Game"), tr("Type"), tr("Size"), tr("Path")});
  Tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
  Tree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  Tree->header()->setSectionResizeMode(3, QHeaderView::Stretch);
  connect(Tree, &QTreeWidget::itemSelectionChanged, this, &ScanDialog::OnSelectionChanged);
  Layout->addWidget(Tree);

  Detail = new QLabel(this);
  Detail->setWordWrap(true);
  Detail->setTextFormat(Qt::RichText);
  Detail->setMinimumHeight(56);
  Layout->addWidget(Detail);

  auto* Buttons = new QDialogButtonBox(this);
  auto* Import = Buttons->addButton(tr("Import selected"), QDialogButtonBox::AcceptRole);
  connect(Import, &QPushButton::clicked, this, &ScanDialog::OnImport);
  auto* Close = Buttons->addButton(tr("Close"), QDialogButtonBox::RejectRole);
  connect(Close, &QPushButton::clicked, this, &QDialog::accept);
  Layout->addWidget(Buttons);

  Populate();
}

void ScanDialog::Populate() {
  QApplication::setOverrideCursor(Qt::WaitCursor);
  Candidates = Discovery::ScanLibraries(Sess.Reg());
  KnownHints = Hints::Load();
  QApplication::restoreOverrideCursor();

  Tree->clear();

  if (Candidates.empty()) {
    Detail->setText(tr("<b>Nothing found.</b> Check the game libraries under Locations -- add the directory your "
                       "games are installed in if it is not listed."));
    return;
  }

  QTreeWidgetItem* Group {};
  QString GroupName;
  for (size_t I = 0; I < Candidates.size(); ++I) {
    const auto& C = Candidates[I];
    if (!Group || GroupName != Q(C.Name)) {
      GroupName = Q(C.Name);
      Group = new QTreeWidgetItem(Tree, {GroupName});
      Group->setFirstColumnSpanned(true);
      Group->setExpanded(true);
    }

    auto* Item = new QTreeWidgetItem(
      Group, {std::filesystem::path {C.Path}.filename().string().c_str(), Describe(C.Binary), HumanSize(C.SizeBytes), Q(C.Path)});
    Item->setData(0, Qt::UserRole, static_cast<qulonglong>(I));
  }
}

void ScanDialog::OnSelectionChanged() {
  const auto Selected = Tree->selectedItems();
  if (Selected.isEmpty()) {
    Detail->clear();
    return;
  }

  const auto Data = Selected.first()->data(0, Qt::UserRole);
  if (!Data.isValid()) {
    Detail->clear();
    return;
  }

  const auto& C = Candidates[Data.toULongLong()];
  QString Text = QStringLiteral("<b>%1</b><br>%2").arg(Q(C.Name).toHtmlEscaped(), Q(C.Path).toHtmlEscaped());
  if (C.SteamAppId) {
    Text += tr("<br>Steam appid %1").arg(C.SteamAppId);
  }

  // If measured tuning exists for this title, say so before importing rather
  // than applying anything behind the user's back.
  const auto Basename = std::filesystem::path {C.Path}.filename().string();
  if (const Hints::Hint* Hint = Hints::Match(KnownHints, Basename, C.SteamAppId)) {
    QString Settings;
    for (const auto& [Key, Value] : Hint->Fex) {
      if (!Settings.isEmpty()) {
        Settings += QLatin1Char(' ');
      }
      Settings += Q(fmt::format("FEX_{}={}", Key, Value));
    }
    Text += QStringLiteral("<br><br><b>%1</b> %2<br><i>%3</i>").arg(tr("Known tuning:"), Settings.toHtmlEscaped(), Q(Hint->Why).toHtmlEscaped());
  }

  Detail->setText(Text);
}

void ScanDialog::OnImport() {
  const auto Selected = Tree->selectedItems();
  if (Selected.isEmpty()) {
    QMessageBox::information(this, tr("Import"), tr("Select one or more executables first."));
    return;
  }

  for (const auto* Item : Selected) {
    const auto Data = Item->data(0, Qt::UserRole);
    if (!Data.isValid()) {
      continue; // A group header.
    }

    const auto& C = Candidates[Data.toULongLong()];

    Title T;
    T.Name = C.Name;
    T.Kind = C.Kind;
    T.Exe = C.Path;
    T.WorkDir = C.WorkDir;

    // Ids stay unique so two installs sharing a folder name can coexist.
    T.Id = MakeId(C.Name);
    int Suffix = 2;
    while (Sess.Reg().FindTitle(T.Id)) {
      T.Id = fmt::format("{}-{}", MakeId(C.Name), Suffix++);
    }

    const auto Basename = std::filesystem::path {C.Path}.filename().string();
    if (const Hints::Hint* Hint = Hints::Match(KnownHints, Basename, C.SteamAppId)) {
      QString Settings;
      for (const auto& [Key, Value] : Hint->Fex) {
        if (!Settings.isEmpty()) {
          Settings += QLatin1Char(' ');
        }
        Settings += Q(fmt::format("FEX_{}={}", Key, Value));
      }
      const auto Answer = QMessageBox::question(this, tr("Known tuning for %1").arg(Q(C.Name)),
                                                tr("%1\n\nApply it?\n\n%2").arg(Q(Hint->Why), Settings), QMessageBox::Yes | QMessageBox::No);
      if (Answer == QMessageBox::Yes) {
        T.Fex = Hint->Fex;
      }
    }

    Sess.Reg().Titles.push_back(std::move(T));
    Added = true;
  }

  accept();
}

} // namespace FastPPCx86::Launcher
