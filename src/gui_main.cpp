#include <QApplication>
#include <QIcon>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMessageBox>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QStatusBar>
#include <QTabWidget>
#include <QThread>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>
#include <cstring>
#include <functional>

#include "aes_cipher.hpp"
#include "digital_sign.hpp"

// ─────────────────────────────────────────────────────────────────────────────
// QLineEdit that accepts dropped file paths
// ─────────────────────────────────────────────────────────────────────────────

class DropEdit : public QLineEdit {
    Q_OBJECT
public:
    explicit DropEdit(QWidget* p = nullptr) : QLineEdit(p) { setAcceptDrops(true); }
protected:
    void dragEnterEvent(QDragEnterEvent* e) override {
        if (e->mimeData()->hasUrls()) e->acceptProposedAction();
    }
    void dropEvent(QDropEvent* e) override {
        const auto urls = e->mimeData()->urls();
        if (!urls.isEmpty()) setText(urls.first().toLocalFile());
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Background worker
// ─────────────────────────────────────────────────────────────────────────────

class Worker : public QThread {
    Q_OBJECT
public:
    std::function<void()> task;
signals:
    void done(bool ok, QString error);
protected:
    void run() override {
        try {
            task();
            emit done(true, {});
        } catch (const std::exception& e) {
            emit done(false, QString::fromStdString(e.what()));
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (anonymous namespace)
// ─────────────────────────────────────────────────────────────────────────────

namespace {

// File-picker row: DropEdit + "Обзор…"
QWidget* makeFileRow(DropEdit*& edit, bool forOpen, QWidget* parent) {
    auto* row = new QWidget(parent);
    auto* h   = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(6);
    edit = new DropEdit(row);
    edit->setPlaceholderText(forOpen ? "Перетащите файл или нажмите «Обзор…»"
                                     : "Путь к выходному файлу…");
    auto* btn = new QPushButton("Обзор…", row);
    btn->setFixedWidth(80);
    QObject::connect(btn, &QPushButton::clicked, [edit, forOpen, parent]() {
        QString p = forOpen
            ? QFileDialog::getOpenFileName(parent, "Открыть файл")
            : QFileDialog::getSaveFileName(parent, "Сохранить как");
        if (!p.isEmpty()) edit->setText(p);
    });
    h->addWidget(edit);
    h->addWidget(btn);
    return row;
}

// Password row: masked edit + 👁 toggle
QWidget* makePwRow(QLineEdit*& edit, const QString& hint, QWidget* parent) {
    auto* row = new QWidget(parent);
    auto* h   = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(6);
    edit = new QLineEdit(row);
    edit->setEchoMode(QLineEdit::Password);
    edit->setPlaceholderText(hint);
    auto* eye = new QPushButton("👁", row);
    eye->setFixedWidth(34);
    eye->setCheckable(true);
    eye->setToolTip("Показать / скрыть пароль");
    QObject::connect(eye, &QPushButton::toggled, [edit](bool on) {
        edit->setEchoMode(on ? QLineEdit::Normal : QLineEdit::Password);
    });
    h->addWidget(edit);
    h->addWidget(eye);
    return row;
}

// Read-only hex field + "Копировать" button.
// fullTextFn() is called on each click to get the full text (may differ from display).
QWidget* makeCopyRow(QLineEdit* display, std::function<QString()> fullTextFn, QWidget* parent) {
    auto* row = new QWidget(parent);
    auto* h   = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(4);
    h->addWidget(display);
    auto* copy = new QPushButton("Копировать", row);
    copy->setFixedWidth(90);
    QObject::connect(copy, &QPushButton::clicked,
                     [fn = std::move(fullTextFn)]() {
                         QApplication::clipboard()->setText(fn());
                     });
    h->addWidget(copy);
    return row;
}

// Returns the platform's default monospace font at the given point size.
// QFont("Monospace") works on Linux via fontconfig but not on Windows;
// QFontDatabase::systemFont(FixedFont) resolves correctly on all platforms.
QFont monoFont(int pt) {
    QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    f.setPointSize(pt);
    return f;
}

QString toHex(const uint8_t* data, size_t n) {
    QString s;
    s.reserve(int(n) * 2);
    for (size_t i = 0; i < n; ++i)
        s += QString("%1").arg(data[i], 2, 16, QChar('0'));
    return s;
}

// Parsed components of an .enc file
struct EncParts {
    QByteArray ciphertext;   // raw ciphertext bytes
    QByteArray tag;          // auth tag bytes (16 AEAD or 32 HMAC)
    bool       is_aead;
    QString    mode_name;
};

// Returns nullopt if file is not a valid .enc
std::optional<EncParts> parseEncFile(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};

    const qint64 fsz = f.size();
    const qint64 hsz = static_cast<qint64>(sizeof(crypto::FileHeader));
    if (fsz < hsz) return {};

    crypto::FileHeader hdr{};
    if (f.read(reinterpret_cast<char*>(&hdr), hsz) != hsz) return {};
    if (std::memcmp(hdr.magic, crypto::FileHeader::MAGIC, 4) != 0) return {};
    if (hdr.mode > static_cast<uint8_t>(crypto::Mode::SIV)) return {};

    const auto   mode = static_cast<crypto::Mode>(hdr.mode);
    const qint64 tsz  = static_cast<qint64>(crypto::auth_tag_size(mode));
    if (fsz < hsz + tsz) return {};

    const qint64 ctsz = fsz - hsz - tsz;

    f.seek(hsz);
    QByteArray ct = f.read(ctsz);

    f.seek(fsz - tsz);
    QByteArray tag = f.read(tsz);

    return EncParts{ct, tag, crypto::mode_is_aead(mode),
                    QString::fromStdString(crypto::mode_to_string(mode))};
}

// Human-readable file info for the Info tab
QString buildFileInfo(const QString& path) {
    auto p = parseEncFile(path);
    if (!p) return "Не удалось разобрать файл .enc.";

    QFile f(path);
    f.open(QIODevice::ReadOnly);
    crypto::FileHeader hdr{};
    f.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));

    return QString(
        "Файл         : %1\n"
        "Режим        : AES-256-%2\n"
        "AEAD         : %3\n"
        "Шифртекст    : %4 байт\n"
        "Соль         : %5\n"
        "IV / Nonce   : %6\n"
        "%7: %8\n"
        "KDF          : PBKDF2-HMAC-SHA256, %9 итераций\n"
        "Целостность  : %10")
        .arg(path)
        .arg(p->mode_name)
        .arg(p->is_aead ? "да" : "нет")
        .arg(p->ciphertext.size())
        .arg(toHex(hdr.salt, crypto::SALT_LEN))
        .arg(toHex(hdr.iv,   crypto::IV_LEN))
        .arg(p->is_aead ? "AEAD-тег     " : "HMAC-SHA256  ")
        .arg(QString::fromLatin1(p->tag.toHex()))
        .arg(crypto::PBKDF2_ITERATIONS)
        .arg(p->is_aead
             ? "AEAD-тег (16 байт, встроен в файл)"
             : "Encrypt-then-MAC (HMAC-SHA256, 32 байта)");
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Main window
// ─────────────────────────────────────────────────────────────────────────────

class CryptografWindow : public QMainWindow {
    Q_OBJECT

    QPlainTextEdit* log_  = nullptr;
    Worker*         work_ = nullptr;

    void logMsg(const QString& msg) {
        const auto ts = QDateTime::currentDateTime().toString("hh:mm:ss");
        log_->appendPlainText(QStringLiteral("[%1] %2").arg(ts, msg));
    }

    void setBusy(bool busy) {
        for (auto* b : findChildren<QPushButton*>(QStringLiteral("opBtn")))
            b->setEnabled(!busy);
        statusBar()->showMessage(busy ? "Выполняется операция…" : "Готово.");
    }

    // ─── Encrypt tab ────────────────────────────────────────────────────────
    QWidget* makeEncryptTab() {
        struct ModeInfo { const char* name; crypto::Mode mode; const char* desc; };
        static const ModeInfo MODES[] = {
            {"ECB",     crypto::Mode::ECB,
             "Electronic Code Book — без IV, детерминированный; нежелательно для секретных данных"},
            {"CBC",     crypto::Mode::CBC,
             "Cipher Block Chaining — случайный IV, последовательный"},
            {"CFB",     crypto::Mode::CFB,
             "Cipher Feedback — случайный IV, самосинхронизирующийся поток"},
            {"OFB",     crypto::Mode::OFB,
             "Output Feedback — случайный IV, ключевой поток независим от данных"},
            {"CTR",     crypto::Mode::CTR,
             "Counter — случайный IV, параллелизуемый"},
            {"GCM",     crypto::Mode::GCM,
             "Galois/Counter Mode — NIST SP 800-38D, 12-байтный nonce, потоковый (AEAD)"},
            {"CCM",     crypto::Mode::CCM,
             "Counter with CBC-MAC — NIST SP 800-38C, полная буферизация (*) (AEAD)"},
            {"GCM-SIV", crypto::Mode::GCM_SIV,
             "GCM-SIV (RFC 8452) — устойчив к повторному использованию nonce (AEAD)"},
            {"SIV",     crypto::Mode::SIV,
             "AES-SIV (RFC 5297) — детерминированный, без nonce, устойчив к повторному использованию (AEAD)"},
        };

        // ── Outer tab (scroll area so result panel never overflows) ──────────
        auto* scroll  = new QScrollArea;
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);

        auto* tab  = new QWidget;
        auto* vlay = new QVBoxLayout(tab);
        vlay->setContentsMargins(0, 0, 0, 0);
        vlay->setSpacing(8);
        scroll->setWidget(tab);

        // ── Input form ───────────────────────────────────────────────────────
        auto* form = new QFormLayout;
        form->setSpacing(7);
        form->setContentsMargins(12, 8, 12, 6);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addLayout(form);

        // Mode
        auto* combo = new QComboBox;
        for (const auto& m : MODES) combo->addItem(m.name);
        combo->setCurrentIndex(4);

        auto* desc = new QLabel(MODES[4].desc);
        desc->setWordWrap(true);
        desc->setStyleSheet("color:#555; font-size:11px;");
        connect(combo, &QComboBox::currentIndexChanged, [desc](int i) {
            if (i >= 0 && i < 9) desc->setText(MODES[i].desc);
        });
        form->addRow("Режим:", combo);
        form->addRow("",       desc);

        // Files
        DropEdit *inEdit, *outEdit;
        form->addRow("Входной файл:",  makeFileRow(inEdit,  true,  tab));
        form->addRow("Выходной файл:", makeFileRow(outEdit, false, tab));
        connect(inEdit, &QLineEdit::textChanged, [outEdit](const QString& t) {
            if (outEdit->text().isEmpty() && !t.isEmpty())
                outEdit->setText(t + ".enc");
        });

        // Passwords
        QLineEdit *pw1, *pw2;
        form->addRow("Пароль:",        makePwRow(pw1, "Введите пароль…",   tab));
        form->addRow("Подтверждение:", makePwRow(pw2, "Повторите пароль…", tab));

        // Encrypt button
        auto* btn = new QPushButton("  Зашифровать");
        btn->setObjectName("opBtn");
        btn->setMinimumHeight(34);
        btn->setStyleSheet(
            "QPushButton          { background:#2563eb; color:white; border-radius:6px;"
            "                       font-weight:bold; font-size:14px; }"
            "QPushButton:hover    { background:#1d4ed8; }"
            "QPushButton:disabled { background:#93c5fd; color:#e0eafe; }");
        form->addRow("", btn);

        // ── Result panel (hidden until encryption succeeds) ──────────────────
        auto* resultBox = new QGroupBox("Результат шифрования");
        resultBox->setVisible(false);
        auto* rform = new QFormLayout(resultBox);
        rform->setSpacing(6);
        rform->setContentsMargins(10, 6, 10, 6);
        rform->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        rform->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

        // Ciphertext field (shows truncated hex; copy reads full bytes from file)
        auto* ctDisplay = new QLineEdit;
        ctDisplay->setReadOnly(true);
        ctDisplay->setFont(monoFont(9));
        ctDisplay->setPlaceholderText("hex-представление шифртекста…");

        auto getCTHex = [outEdit]() -> QString {
            auto parts = parseEncFile(outEdit->text().trimmed());
            return parts ? QString::fromLatin1(parts->ciphertext.toHex()) : QString{};
        };
        rform->addRow("Шифртекст:", makeCopyRow(ctDisplay, getCTHex, resultBox));

        // Authentication tag field (always shows full hex)
        auto* tagLabel   = new QLabel("Имитовставка:");
        auto* tagDisplay = new QLineEdit;
        tagDisplay->setReadOnly(true);
        tagDisplay->setFont(monoFont(9));
        tagDisplay->setPlaceholderText("hex-представление тега аутентификации…");

        auto getTagHex = [tagDisplay]() { return tagDisplay->text(); };
        rform->addRow(tagLabel, makeCopyRow(tagDisplay, getTagHex, resultBox));

        vlay->addWidget(resultBox);
        vlay->addStretch(1);

        // ── Button handler ───────────────────────────────────────────────────
        connect(btn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = inEdit->text().trimmed();
            const QString out = outEdit->text().trimmed();
            const QString p1  = pw1->text();
            const QString p2  = pw2->text();
            const int     mi  = combo->currentIndex();

            if (in.isEmpty())       { QMessageBox::warning(this, "Ошибка", "Укажите входной файл.");          return; }
            if (out.isEmpty())      { QMessageBox::warning(this, "Ошибка", "Укажите выходной файл.");         return; }
            if (p1.isEmpty())       { QMessageBox::warning(this, "Ошибка", "Пароль не должен быть пустым.");  return; }
            if (p1 != p2)           { QMessageBox::warning(this, "Ошибка", "Пароли не совпадают.");           return; }
            if (!QFile::exists(in)) { QMessageBox::warning(this, "Ошибка", "Входной файл не найден.");        return; }
            if (QFile::exists(out)) {
                if (QMessageBox::question(this, "Файл существует",
                        QString("'%1' уже существует.\nПерезаписать?").arg(out))
                        != QMessageBox::Yes) return;
                QFile::remove(out);
            }

            resultBox->setVisible(false);

            const auto inS  = in.toStdString();
            const auto outS = out.toStdString();
            const auto pwS  = p1.toStdString();
            const auto mode = MODES[mi].mode;

            setBusy(true);
            logMsg(QString("Шифрование [%1]: %2  →  %3")
                   .arg(combo->currentText(), in, out));

            work_ = new Worker;
            work_->task = [inS, outS, pwS, mode]() {
                crypto::encrypt_file(inS, outS, pwS, mode);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) {
                    // Parse output file and populate result panel
                    auto parts = parseEncFile(out);
                    if (parts) {
                        // Ciphertext: show first 24 bytes as hex, note size
                        constexpr int PREVIEW = 24;
                        const QByteArray& ct = parts->ciphertext;
                        if (ct.size() <= PREVIEW) {
                            ctDisplay->setText(QString::fromLatin1(ct.toHex()));
                        } else {
                            ctDisplay->setText(
                                QString::fromLatin1(ct.left(PREVIEW).toHex()) +
                                QString("…  (%1 байт)").arg(ct.size()));
                        }

                        // Tag label: "Имитовставка" for AEAD, "HMAC-SHA256" for non-AEAD
                        tagLabel->setText(parts->is_aead ? "Имитовставка:" : "HMAC-SHA256:");
                        tagDisplay->setText(QString::fromLatin1(parts->tag.toHex()));

                        resultBox->setVisible(true);
                    }

                    logMsg(QString("✓ Готово. Шифртекст: %1 байт, тег: %2 байт")
                           .arg(parts ? parts->ciphertext.size() : 0)
                           .arg(parts ? parts->tag.size()        : 0));
                } else {
                    QFile::remove(out);
                    logMsg(QString("✗ Ошибка: %1").arg(err));
                    QMessageBox::critical(this, "Ошибка шифрования", err);
                }
                work_->deleteLater();
                work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        return scroll;
    }

    // ─── Decrypt tab ────────────────────────────────────────────────────────
    QWidget* makeDecryptTab() {
        auto* tab  = new QWidget;
        auto* form = new QFormLayout(tab);
        form->setSpacing(7);
        form->setContentsMargins(12, 8, 12, 8);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

        DropEdit *inEdit, *outEdit;
        form->addRow("Зашифрованный файл:", makeFileRow(inEdit,  true,  tab));
        form->addRow("Выходной файл:",      makeFileRow(outEdit, false, tab));

        connect(inEdit, &QLineEdit::textChanged, [outEdit](const QString& t) {
            if (outEdit->text().isEmpty() && !t.isEmpty()) {
                QString out = t;
                if (out.endsWith(".enc", Qt::CaseInsensitive)) out.chop(4);
                else                                            out += ".dec";
                outEdit->setText(out);
            }
        });

        QLineEdit* pw;
        form->addRow("Пароль:", makePwRow(pw, "Введите пароль…", tab));

        auto* btn = new QPushButton("  Расшифровать");
        btn->setObjectName("opBtn");
        btn->setMinimumHeight(34);
        btn->setStyleSheet(
            "QPushButton          { background:#16a34a; color:white; border-radius:6px;"
            "                       font-weight:bold; font-size:14px; }"
            "QPushButton:hover    { background:#15803d; }"
            "QPushButton:disabled { background:#86efac; color:#dcfce7; }");
        form->addRow("", btn);

        connect(btn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = inEdit->text().trimmed();
            const QString out = outEdit->text().trimmed();
            const QString p   = pw->text();

            if (in.isEmpty())       { QMessageBox::warning(this, "Ошибка", "Укажите файл для расшифрования."); return; }
            if (out.isEmpty())      { QMessageBox::warning(this, "Ошибка", "Укажите выходной файл.");           return; }
            if (p.isEmpty())        { QMessageBox::warning(this, "Ошибка", "Пароль не должен быть пустым.");    return; }
            if (!QFile::exists(in)) { QMessageBox::warning(this, "Ошибка", "Входной файл не найден.");          return; }
            if (QFile::exists(out)) {
                if (QMessageBox::question(this, "Файл существует",
                        QString("'%1' уже существует.\nПерезаписать?").arg(out))
                        != QMessageBox::Yes) return;
                QFile::remove(out);
            }

            const auto inS  = in.toStdString();
            const auto outS = out.toStdString();
            const auto pwS  = p.toStdString();

            setBusy(true);
            logMsg(QString("Расшифрование: %1  →  %2").arg(in, out));

            work_ = new Worker;
            work_->task = [inS, outS, pwS]() {
                crypto::decrypt_file(inS, outS, pwS);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) {
                    logMsg(QString("✓ Готово. Размер: %1 байт").arg(QFileInfo(out).size()));
                } else {
                    QFile::remove(out);
                    logMsg(QString("✗ Ошибка: %1").arg(err));
                    QMessageBox::critical(this, "Ошибка расшифрования", err);
                }
                work_->deleteLater();
                work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        return tab;
    }

    // ─── Sign tab ───────────────────────────────────────────────────────────
    QWidget* makeSignTab() {
        auto* scroll = new QScrollArea;
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);

        auto* tab  = new QWidget;
        auto* vlay = new QVBoxLayout(tab);
        vlay->setContentsMargins(10, 8, 10, 8);
        vlay->setSpacing(8);
        scroll->setWidget(tab);

        // ── 1. Key generation ────────────────────────────────────────────────
        auto* keyBox  = new QGroupBox("Генерация ключевой пары (ECDSA P-256)");
        auto* keyForm = new QFormLayout(keyBox);
        keyForm->setSpacing(7);
        keyForm->setContentsMargins(10, 6, 10, 6);
        keyForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        keyForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

        DropEdit *privEdit, *pubEdit;
        keyForm->addRow("Закрытый ключ:", makeFileRow(privEdit, false, tab));
        keyForm->addRow("Открытый ключ:", makeFileRow(pubEdit,  false, tab));

        auto* keyBtn = new QPushButton("  Сгенерировать");
        keyBtn->setObjectName("opBtn");
        keyBtn->setMinimumHeight(34);
        keyBtn->setStyleSheet(
            "QPushButton          { background:#7c3aed; color:white; border-radius:6px;"
            "                       font-weight:bold; font-size:13px; }"
            "QPushButton:hover    { background:#6d28d9; }"
            "QPushButton:disabled { background:#c4b5fd; color:#ede9fe; }");
        keyForm->addRow("", keyBtn);
        vlay->addWidget(keyBox);

        connect(keyBtn, &QPushButton::clicked, this, [=, this]() {
            const QString priv = privEdit->text().trimmed();
            const QString pub  = pubEdit->text().trimmed();
            if (priv.isEmpty()) { QMessageBox::warning(this, "Ошибка", "Укажите путь для закрытого ключа."); return; }
            if (pub.isEmpty())  { QMessageBox::warning(this, "Ошибка", "Укажите путь для открытого ключа."); return; }
            setBusy(true);
            logMsg(QString("Генерация ключей ECDSA P-256…"));
            work_ = new Worker;
            work_->task = [p = priv.toStdString(), q = pub.toStdString()]() {
                crypto::generate_ec_keypair(p, q);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) logMsg("✓ Ключи сохранены: " + priv + " / " + pub);
                else  { logMsg("✗ " + err); QMessageBox::critical(this, "Ошибка", err); }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        // ── 2. Sign ──────────────────────────────────────────────────────────
        auto* signBox  = new QGroupBox("Подписать файл");
        auto* signForm = new QFormLayout(signBox);
        signForm->setSpacing(7);
        signForm->setContentsMargins(10, 6, 10, 6);
        signForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        signForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

        DropEdit *sInEdit, *sKeyEdit, *sSigEdit;
        signForm->addRow("Файл:",           makeFileRow(sInEdit,  true,  tab));
        signForm->addRow("Закрытый ключ:", makeFileRow(sKeyEdit, true,  tab));
        signForm->addRow("Файл подписи:",  makeFileRow(sSigEdit, false, tab));

        connect(sInEdit, &QLineEdit::textChanged, [sSigEdit](const QString& t) {
            if (sSigEdit->text().isEmpty() && !t.isEmpty())
                sSigEdit->setText(t + ".sig");
        });

        auto* signBtn = new QPushButton("  Подписать");
        signBtn->setObjectName("opBtn");
        signBtn->setMinimumHeight(34);
        signBtn->setStyleSheet(
            "QPushButton          { background:#0369a1; color:white; border-radius:6px;"
            "                       font-weight:bold; font-size:13px; }"
            "QPushButton:hover    { background:#075985; }"
            "QPushButton:disabled { background:#7dd3fc; color:#e0f2fe; }");
        signForm->addRow("", signBtn);
        vlay->addWidget(signBox);

        connect(signBtn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = sInEdit->text().trimmed();
            const QString key = sKeyEdit->text().trimmed();
            const QString sig = sSigEdit->text().trimmed();
            if (in.isEmpty())          { QMessageBox::warning(this, "Ошибка", "Укажите подписываемый файл.");   return; }
            if (key.isEmpty())         { QMessageBox::warning(this, "Ошибка", "Укажите файл закрытого ключа."); return; }
            if (sig.isEmpty())         { QMessageBox::warning(this, "Ошибка", "Укажите путь для подписи.");     return; }
            if (!QFile::exists(in))    { QMessageBox::warning(this, "Ошибка", "Файл не найден.");               return; }
            if (!QFile::exists(key))   { QMessageBox::warning(this, "Ошибка", "Ключ не найден.");               return; }
            setBusy(true);
            logMsg("Подпись файла: " + in);
            work_ = new Worker;
            work_->task = [i = in.toStdString(), k = key.toStdString(), s = sig.toStdString()]() {
                crypto::sign_file(i, k, s);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) logMsg("✓ Подпись записана: " + sig);
                else  { logMsg("✗ " + err); QMessageBox::critical(this, "Ошибка подписи", err); }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        // ── 3. Verify ────────────────────────────────────────────────────────
        auto* verBox  = new QGroupBox("Проверить подпись");
        auto* verForm = new QFormLayout(verBox);
        verForm->setSpacing(7);
        verForm->setContentsMargins(10, 6, 10, 6);
        verForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        verForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

        DropEdit *vInEdit, *vSigEdit, *vKeyEdit;
        verForm->addRow("Файл:",           makeFileRow(vInEdit,  true, tab));
        verForm->addRow("Файл подписи:",  makeFileRow(vSigEdit, true, tab));
        verForm->addRow("Открытый ключ:", makeFileRow(vKeyEdit, true, tab));

        auto* verBtn = new QPushButton("  Проверить");
        verBtn->setObjectName("opBtn");
        verBtn->setMinimumHeight(34);
        verBtn->setStyleSheet(
            "QPushButton          { background:#16a34a; color:white; border-radius:6px;"
            "                       font-weight:bold; font-size:13px; }"
            "QPushButton:hover    { background:#15803d; }"
            "QPushButton:disabled { background:#86efac; color:#dcfce7; }");
        verForm->addRow("", verBtn);
        vlay->addWidget(verBox);
        vlay->addStretch(1);

        connect(verBtn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = vInEdit->text().trimmed();
            const QString sig = vSigEdit->text().trimmed();
            const QString key = vKeyEdit->text().trimmed();
            if (in.isEmpty())        { QMessageBox::warning(this, "Ошибка", "Укажите проверяемый файл.");   return; }
            if (sig.isEmpty())       { QMessageBox::warning(this, "Ошибка", "Укажите файл подписи.");       return; }
            if (key.isEmpty())       { QMessageBox::warning(this, "Ошибка", "Укажите файл открытого ключа."); return; }
            if (!QFile::exists(in))  { QMessageBox::warning(this, "Ошибка", "Файл не найден.");             return; }
            if (!QFile::exists(sig)) { QMessageBox::warning(this, "Ошибка", "Файл подписи не найден.");     return; }
            if (!QFile::exists(key)) { QMessageBox::warning(this, "Ошибка", "Ключ не найден.");             return; }
            setBusy(true);
            logMsg("Проверка подписи: " + in);
            work_ = new Worker;
            bool* result = new bool(false);
            work_->task = [i = in.toStdString(), s = sig.toStdString(),
                           k = key.toStdString(), result]() {
                *result = crypto::verify_file(i, s, k);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) {
                    if (*result) {
                        logMsg("✓ Подпись ВЕРНА. Файл не изменён.");
                        QMessageBox::information(this, "Результат проверки",
                            "Подпись верна.\nФайл не был изменён после подписания.");
                    } else {
                        logMsg("✗ Подпись НЕДЕЙСТВИТЕЛЬНА. Файл изменён или ключ неверен.");
                        QMessageBox::critical(this, "Результат проверки",
                            "Подпись недействительна!\nФайл мог быть изменён, или используется другой ключ.");
                    }
                } else {
                    logMsg("✗ " + err);
                    QMessageBox::critical(this, "Ошибка проверки", err);
                }
                delete result;
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        return scroll;
    }

    // ─── Info tab ───────────────────────────────────────────────────────────
    QWidget* makeInfoTab() {
        auto* tab  = new QWidget;
        auto* vlay = new QVBoxLayout(tab);
        vlay->setContentsMargins(12, 8, 12, 8);
        vlay->setSpacing(6);

        auto* row       = new QWidget;
        auto* h         = new QHBoxLayout(row);
        auto* lbl       = new QLabel("Файл:");
        auto* fileEdit  = new DropEdit;
        auto* browseBtn = new QPushButton("Обзор…");
        h->setContentsMargins(0, 0, 0, 0);
        h->setSpacing(6);
        lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        lbl->setFixedWidth(50);
        fileEdit->setPlaceholderText("Перетащите или выберите .enc файл…");
        browseBtn->setFixedWidth(80);
        h->addWidget(lbl);
        h->addWidget(fileEdit);
        h->addWidget(browseBtn);
        vlay->addWidget(row);

        connect(browseBtn, &QPushButton::clicked, [fileEdit, this]() {
            auto p = QFileDialog::getOpenFileName(
                this, "Открыть зашифрованный файл",
                {}, "Зашифрованные файлы (*.enc);;Все файлы (*)");
            if (!p.isEmpty()) fileEdit->setText(p);
        });

        auto* view = new QPlainTextEdit;
        view->setReadOnly(true);
        view->setFont(monoFont(10));
        view->setPlaceholderText("Информация о файле появится здесь…");
        vlay->addWidget(view, 1);

        connect(fileEdit, &QLineEdit::textChanged, [view](const QString& t) {
            view->setPlainText(t.isEmpty() ? QString{} : buildFileInfo(t));
        });

        return tab;
    }

public:
    explicit CryptografWindow(QWidget* parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("Cryptograf — AES-256 шифрование файлов");
        resize(700, 520);
        setMinimumSize(520, 420);

        auto* central = new QWidget;
        setCentralWidget(central);
        auto* vlay = new QVBoxLayout(central);
        vlay->setContentsMargins(6, 6, 6, 4);
        vlay->setSpacing(4);

        auto* tabs = new QTabWidget;
        tabs->setDocumentMode(true);
        tabs->addTab(makeEncryptTab(), " Шифровать ");
        tabs->addTab(makeDecryptTab(), " Расшифровать ");
        tabs->addTab(makeSignTab(),    " Подпись ");
        tabs->addTab(makeInfoTab(),    " Информация ");
        vlay->addWidget(tabs, 1);

        auto* logGroup = new QGroupBox("Журнал");
        auto* logLay   = new QVBoxLayout(logGroup);
        logLay->setContentsMargins(4, 2, 4, 2);
        log_ = new QPlainTextEdit;
        log_->setReadOnly(true);
        log_->setMaximumHeight(72);
        log_->setFont(monoFont(9));
        log_->setStyleSheet(
            "QPlainTextEdit { background:#1e1e1e; color:#d4d4d4; border:none; }");
        logLay->addWidget(log_);
        vlay->addWidget(logGroup);

        auto* note = new QLabel(
            "(*) CCM буферизирует весь файл в памяти. "
            "GCM-SIV реализован по RFC 8452 без зависимости от OpenSSL ≥ 3.2.");
        note->setStyleSheet("color:#888; font-size:10px;");
        note->setWordWrap(true);
        vlay->addWidget(note);

        statusBar()->showMessage("Готово.");
        logMsg("Cryptograf запущен. Поддерживаемые режимы: ECB, CBC, CFB, OFB, CTR, GCM, CCM, GCM-SIV, SIV.");
    }
};

#include "gui_main.moc"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("Cryptograf");
    app.setApplicationDisplayName("Cryptograf — AES-256");
    app.setWindowIcon(QIcon(":/cryptograf.png"));
    app.setStyle("Fusion");
    CryptografWindow w;
    w.show();
    return app.exec();
}
