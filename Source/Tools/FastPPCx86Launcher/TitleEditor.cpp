// SPDX-License-Identifier: MIT
#include "TitleEditor.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

#include <filesystem>

namespace FastPPCx86::Launcher {

namespace {
  QString Q(const std::string& Text) {
    return QString::fromStdString(Text);
  }

  std::vector<std::string> SplitArgs(const QString& Text) {
    std::vector<std::string> Args;
    for (const auto& Part : Text.split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
      Args.push_back(Part.toStdString());
    }
    return Args;
  }
} // namespace

TitleEditor::TitleEditor(Title& T, QWidget* Parent)
  : QDialog(Parent)
  , Edited(T) {
  setWindowTitle(tr("Edit title"));
  resize(720, 520);

  auto* Layout = new QVBoxLayout(this);
  auto* Form = new QFormLayout;

  Name = new QLineEdit(Q(T.Name), this);
  Form->addRow(tr("Name"), Name);

  Kind = new QComboBox(this);
  Kind->addItem(tr("Native (x86 Linux binary)"), "native");
  Kind->addItem(tr("Proton (Windows title)"), "proton");
  Kind->addItem(tr("Wine (Windows title, no Proton)"), "wine");
  Kind->addItem(tr("Steam client"), "steam");
  Kind->setCurrentIndex(Kind->findData(Q(std::string {ToString(T.Kind)})));
  Form->addRow(tr("Kind"), Kind);

  auto* ExeRow = new QHBoxLayout;
  Exe = new QLineEdit(Q(T.Exe), this);
  ExeRow->addWidget(Exe, 1);
  auto* Browse = new QPushButton(tr("Browse..."), this);
  connect(Browse, &QPushButton::clicked, this, &TitleEditor::OnBrowse);
  ExeRow->addWidget(Browse);
  Form->addRow(tr("Executable"), ExeRow);

  WorkDir = new QLineEdit(Q(T.WorkDir), this);
  WorkDir->setPlaceholderText(tr("empty: the directory holding the executable"));
  Form->addRow(tr("Working directory"), WorkDir);

  QString ArgText;
  for (const auto& Arg : T.Args) {
    if (!ArgText.isEmpty()) {
      ArgText += QLatin1Char(' ');
    }
    ArgText += Q(Arg);
  }
  Args = new QLineEdit(ArgText, this);
  Form->addRow(tr("Arguments"), Args);

  Prefix = new QLineEdit(Q(T.Prefix), this);
  Prefix->setPlaceholderText(tr("empty: a prefix of this title's own, under the launcher's data directory"));
  Prefix->setToolTip(tr("Every title gets its own prefix. Sharing one between titles is how you end up "
                        "with a prefix nothing runs in."));
  Form->addRow(tr("Wine/Proton prefix"), Prefix);

  Timeout = new QSpinBox(this);
  Timeout->setRange(0, 86400);
  Timeout->setValue(T.TimeoutSeconds);
  Timeout->setSpecialValueText(tr("none"));
  Timeout->setSuffix(tr(" s"));
  // Worth stating plainly: a timeout on a title that takes minutes to reach its
  // menu reads as "it crashes after N seconds".
  Timeout->setToolTip(tr("Kills the title after this long. Leave at none unless you are benchmarking: a "
                         "timeout on a slow-starting title looks exactly like a crash."));
  Form->addRow(tr("Timeout"), Timeout);

  Layout->addLayout(Form);

  auto* EnvLabel = new QLabel(tr("Extra environment, one NAME=VALUE per line. These are the title's own variables "
                                 "(SteamAppId, DOTNET_ROOT and so on), not FEX tuning -- that lives on the Tuning tab."),
                              this);
  EnvLabel->setWordWrap(true);
  Layout->addWidget(EnvLabel);

  Env = new QPlainTextEdit(this);
  QString EnvText;
  for (const auto& [Key, Value] : T.Env) {
    EnvText += Q(Key) + "=" + Q(Value) + "\n";
  }
  Env->setPlainText(EnvText);
  Layout->addWidget(Env);

  auto* Buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  connect(Buttons, &QDialogButtonBox::accepted, this, &TitleEditor::OnAccept);
  connect(Buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
  Layout->addWidget(Buttons);
}

void TitleEditor::OnBrowse() {
  const auto Start =
    Exe->text().isEmpty() ? QString {} : Q(std::filesystem::path {ExpandPath(Exe->text().toStdString())}.parent_path().string());
  const auto Path = QFileDialog::getOpenFileName(this, tr("Choose the executable"), Start);
  if (!Path.isEmpty()) {
    Exe->setText(Path);
  }
}

void TitleEditor::OnAccept() {
  Edited.Name = Name->text().toStdString();
  Edited.Kind = TitleKindFromString(Kind->currentData().toString().toStdString()).value_or(TitleKind::Native);
  Edited.Exe = Exe->text().toStdString();
  Edited.WorkDir = WorkDir->text().toStdString();
  Edited.Args = SplitArgs(Args->text());
  Edited.Prefix = Prefix->text().toStdString();
  Edited.TimeoutSeconds = Timeout->value();

  Edited.Env.clear();
  for (const auto& Line : Env->toPlainText().split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
    const auto Equals = Line.indexOf(QLatin1Char('='));
    if (Equals <= 0) {
      continue;
    }
    Edited.Env[Line.left(Equals).trimmed().toStdString()] = Line.mid(Equals + 1).toStdString();
  }

  accept();
}

} // namespace FastPPCx86::Launcher
