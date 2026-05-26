#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QCheckBox>
#include <QDir>
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
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QMessageBox>
#include <QMimeData>
#include <QPainter>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QSplitter>
#include <QStatusBar>
#include <QTabBar>
#include <QTabWidget>
#include <QTextStream>
#include <QThread>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>
#include <cstring>
#include <functional>
#include <memory>

#include "aes_cipher.hpp"
#include "digital_sign.hpp"
#include "diagram_widgets.hpp"

// ── DropEdit ──────────────────────────────────────────────────────────────────
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

// ── Worker ────────────────────────────────────────────────────────────────────
class Worker : public QThread {
    Q_OBJECT
public:
    std::function<void()> task;
    void reportProgress(qint64 d, qint64 t) { emit progress(d, t); }
signals:
    void done(bool ok, QString error);
    void progress(qint64 done, qint64 total);
protected:
    void run() override {
        try { task(); emit done(true, {}); }
        catch (const std::exception& e) { emit done(false, QString::fromStdString(e.what())); }
    }
};

// ── DotGridWidget: diagram pane background ────────────────────────────────────
class DotGridWidget : public QWidget {
public:
    explicit DotGridWidget(QWidget* p = nullptr) : QWidget(p) {
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    }
    void setDark(bool dark) { dark_ = dark; update(); }
protected:
    bool dark_ = false;
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.fillRect(rect(), dark_ ? QColor("#1a1b26") : QColor("#f7f8fb"));
        painter.setPen(Qt::NoPen);
        painter.setBrush(dark_ ? QColor("#2f3549") : QColor("#cdd0de"));
        const int step = 18, r = 1;
        for (int y = step; y < height(); y += step)
            for (int x = step; x < width(); x += step)
                painter.drawEllipse(x - r, y - r, r * 2, r * 2);
    }
};

// ── Helpers ───────────────────────────────────────────────────────────────────
namespace {

QFont monoFont(int pt) {
    QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    f.setPointSize(pt);
    return f;
}

// Returns 0 (empty) … 4 (very strong)
static int calcStrength(const QString& pw) {
    if (pw.isEmpty()) return 0;
    int s = 0;
    if (pw.length() >= 8)  s++;
    if (pw.length() >= 12) s++;
    bool lo = false, up = false, di = false, sp = false;
    for (QChar c : pw) {
        if      (c.isLower()) lo = true;
        else if (c.isUpper()) up = true;
        else if (c.isDigit()) di = true;
        else                  sp = true;
    }
    if (lo && up)    s++;
    if (di || sp)    s++;
    if (di && sp)    s++;           // bonus: both digits and specials
    return std::min(std::max(s, 1), 4);
}

QString toHex(const uint8_t* data, size_t n) {
    QString s; s.reserve(int(n) * 2);
    for (size_t i = 0; i < n; ++i)
        s += QString("%1").arg(data[i], 2, 16, QChar('0'));
    return s;
}

QWidget* makeFileRow(DropEdit*& edit, bool forOpen, QWidget* parent) {
    auto* row = new QWidget(parent);
    auto* h   = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0); h->setSpacing(6);
    edit = new DropEdit(row);
    edit->setPlaceholderText(forOpen ? "Перетащите файл или нажмите «Обзор…»"
                                     : "Путь к выходному файлу…");
    auto* btn = new QPushButton("Обзор…", row);
    btn->setFixedWidth(76);
    QObject::connect(btn, &QPushButton::clicked, [edit, forOpen, parent]() {
        QString p = forOpen ? QFileDialog::getOpenFileName(parent, "Открыть файл")
                            : QFileDialog::getSaveFileName(parent, "Сохранить как");
        if (!p.isEmpty()) edit->setText(p);
    });
    h->addWidget(edit); h->addWidget(btn);
    return row;
}

QWidget* makePwRow(QLineEdit*& edit, const QString& hint, QWidget* parent) {
    auto* row = new QWidget(parent);
    auto* h   = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0); h->setSpacing(6);
    edit = new QLineEdit(row);
    edit->setEchoMode(QLineEdit::Password);
    edit->setPlaceholderText(hint);
    auto* eye = new QPushButton("●", row);
    eye->setFixedWidth(32); eye->setCheckable(true);
    eye->setObjectName("eyeBtn");
    QObject::connect(eye, &QPushButton::toggled, [edit](bool on) {
        edit->setEchoMode(on ? QLineEdit::Normal : QLineEdit::Password);
    });
    h->addWidget(edit); h->addWidget(eye);
    return row;
}

QWidget* makeCopyRow(QLineEdit* display, std::function<QString()> fullTextFn, QWidget* parent) {
    auto* row = new QWidget(parent);
    auto* h   = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0); h->setSpacing(4);
    h->addWidget(display);
    auto* copy = new QPushButton("Копировать", row);
    copy->setFixedWidth(90); copy->setObjectName("copyBtn");
    QObject::connect(copy, &QPushButton::clicked, [fn = std::move(fullTextFn)]() {
        QApplication::clipboard()->setText(fn());
    });
    h->addWidget(copy);
    return row;
}

struct EncParts {
    QByteArray ciphertext, tag, salt, iv;
    bool       is_aead;
    bool       is_folder;
    QString    mode_name;
};

std::optional<EncParts> parseEncFile(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    const qint64 fsz = f.size(), hsz = sizeof(crypto::FileHeader);
    if (fsz < hsz) return {};
    crypto::FileHeader hdr{};
    if (f.read(reinterpret_cast<char*>(&hdr), hsz) != hsz) return {};
    const bool is_file   = std::memcmp(hdr.magic, crypto::FileHeader::MAGIC,        4) == 0;
    const bool is_folder = std::memcmp(hdr.magic, crypto::FileHeader::FOLDER_MAGIC, 4) == 0;
    if (!is_file && !is_folder) return {};
    if (hdr.mode > static_cast<uint8_t>(crypto::Mode::SIV)) return {};
    const auto   mode = static_cast<crypto::Mode>(hdr.mode);
    const qint64 tsz  = static_cast<qint64>(crypto::auth_tag_size(mode));
    if (fsz < hsz + tsz) return {};
    f.seek(hsz);
    QByteArray ct = f.read(fsz - hsz - tsz);
    f.seek(fsz - tsz);
    return EncParts{
        ct,
        f.read(tsz),
        QByteArray(reinterpret_cast<const char*>(hdr.salt), crypto::SALT_LEN),
        QByteArray(reinterpret_cast<const char*>(hdr.iv),   crypto::IV_LEN),
        crypto::mode_is_aead(mode),
        is_folder,
        QString::fromStdString(crypto::mode_to_string(mode))
    };
}

QString buildFileInfo(const QString& path) {
    auto p = parseEncFile(path);
    if (!p) return "Не удалось разобрать файл .enc.";
    return QString(
        "Файл         : %1\n"
        "Тип          : %2\n"
        "Режим        : AES-256-%3\n"
        "AEAD         : %4\n"
        "Шифртекст    : %5 байт\n"
        "Соль         : %6\n"
        "IV / Nonce   : %7\n"
        "%8: %9\n"
        "KDF          : PBKDF2-HMAC-SHA256, %10 итераций\n"
        "Целостность  : %11")
        .arg(path)
        .arg(p->is_folder ? "Архив папки (CDIR)" : "Файл")
        .arg(p->mode_name)
        .arg(p->is_aead ? "да" : "нет")
        .arg(p->ciphertext.size())
        .arg(QString::fromLatin1(p->salt.toHex()))
        .arg(QString::fromLatin1(p->iv.toHex()))
        .arg(p->is_aead ? "Тег AEAD     " : "HMAC-SHA256  ")
        .arg(QString::fromLatin1(p->tag.toHex()))
        .arg(crypto::PBKDF2_ITERATIONS)
        .arg(p->is_aead ? "AEAD-тег (16 байт, встроен в файл)"
                        : "Encrypt-then-MAC (HMAC-SHA256, 32 байта)");
}


// Wrap a diagram widget in the dot-grid background pane (forward-declared; defined inside class)
static QWidget* wrapDiagram(QWidget* diagram, QWidget* parent, QList<DotGridWidget*>* reg = nullptr) {
    auto* bg   = new DotGridWidget(parent);
    if (reg) reg->append(bg);
    auto* vlay = new QVBoxLayout(bg);
    vlay->setContentsMargins(14, 14, 14, 14);

    auto* scroll = new QScrollArea(bg);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet(
        "QScrollArea { background: transparent; border: none; }"
        "QScrollBar:vertical   { background:#f0f1f7; width:6px; border-radius:3px; }"
        "QScrollBar::handle:vertical { background:#c8cad5; border-radius:3px; min-height:16px; }"
        "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical { height:0; }"
        "QScrollBar:horizontal { background:#f0f1f7; height:6px; border-radius:3px; }"
        "QScrollBar::handle:horizontal { background:#c8cad5; border-radius:3px; min-width:16px; }"
        "QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal { width:0; }");

    diagram->setStyleSheet("background: white; border-radius: 8px;");
    scroll->setWidget(diagram);
    vlay->addWidget(scroll);
    return bg;
}

struct ModeInfo { const char* name; crypto::Mode mode; const char* desc; };
static const ModeInfo MODES[] = {
    {"ECB",     crypto::Mode::ECB,     "Детерминированный, без IV; нежелателен"},
    {"CBC",     crypto::Mode::CBC,     "Cipher Block Chaining — случайный IV"},
    {"CFB",     crypto::Mode::CFB,     "Cipher Feedback — самосинхронизирующийся поток"},
    {"OFB",     crypto::Mode::OFB,     "Output Feedback — ключевой поток ⊥ данным"},
    {"CTR",     crypto::Mode::CTR,     "Counter — параллелизуемый"},
    {"GCM",     crypto::Mode::GCM,     "Galois/Counter Mode — NIST SP 800-38D (AEAD)"},
    {"CCM",     crypto::Mode::CCM,     "Counter with CBC-MAC — NIST SP 800-38C (AEAD)"},
    {"GCM-SIV", crypto::Mode::GCM_SIV, "GCM-SIV RFC 8452 — устойчив к повтору nonce (AEAD)"},
    {"SIV",     crypto::Mode::SIV,     "AES-SIV RFC 5297 — детерминированный, без nonce (AEAD)"},
    {"EAX",     crypto::Mode::EAX,     "EAX — CTR+OMAC двухпроходный AEAD (OpenSSL ≥ 3.0)"},
    {"OCB",     crypto::Mode::OCB,     "OCB3 RFC 7253 — параллельный однопроходный AEAD"},
};
static constexpr int MODE_COUNT = 11;

} // namespace

// ── App stylesheet ────────────────────────────────────────────────────────────
static const char* APP_STYLE = R"qss(
QMainWindow, QWidget#central {
    background: #f7f8fb;
}
QTabWidget::pane {
    border: none;
    background: transparent;
}
QTabBar {
    background: #ffffff;
    border-bottom: 1px solid #dddee5;
}
QTabBar::tab {
    background: transparent;
    color: #7f8090;
    padding: 11px 24px;
    font-size: 13px;
    font-weight: 600;
    border: none;
    border-bottom: 3px solid transparent;
    margin-right: 2px;
}
QTabBar::tab:selected {
    color: #4f46e5;
    border-bottom: 3px solid #4f46e5;
}
QTabBar::tab:hover:!selected {
    color: #2e2f38;
    border-bottom: 3px solid #dddee5;
}
QLabel { color: #2e2f38; font-size: 13px; }
QLineEdit {
    background: white;
    border: 1.5px solid #dddee5;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    color: #2e2f38;
}
QLineEdit:focus { border-color: #4f46e5; }
QLineEdit:read-only { background: #f7f8fb; color: #555666; }
QComboBox {
    background: white;
    border: 1.5px solid #dddee5;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    color: #2e2f38;
    min-height: 28px;
}
QComboBox:focus { border-color: #4f46e5; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background: white;
    border: 1.5px solid #dddee5;
    border-radius: 6px;
    selection-background-color: #eef0fb;
    selection-color: #4f46e5;
    padding: 4px;
}
QPushButton {
    background: #f7f8fb;
    border: 1.5px solid #dddee5;
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 13px;
    color: #2e2f38;
}
QPushButton:hover { background: #eef0fb; border-color: #4f46e5; color: #4f46e5; }
QPushButton:pressed { background: #e0e4f8; }
QPushButton#eyeBtn {
    background: transparent;
    border: 1.5px solid #dddee5;
    border-radius: 6px;
    color: #7f8090;
    font-size: 10px;
    padding: 0;
}
QPushButton#eyeBtn:checked { color: #4f46e5; border-color: #4f46e5; }
QPushButton#copyBtn { font-size: 12px; color: #555666; padding: 5px 10px; }
QGroupBox {
    background: white;
    border: 1.5px solid #dddee5;
    border-radius: 8px;
    margin-top: 8px;
    padding-top: 4px;
    font-size: 12px;
    font-weight: 600;
    color: #555666;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    left: 12px;
    color: #555666;
}
QScrollArea { background: transparent; border: none; }
QScrollBar:vertical {
    background: #f7f8fb; width: 7px; border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #c8cad5; border-radius: 4px; min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QStatusBar { color: #7f8090; font-size: 11px; }
QWidget#formPane { background: white; border-right: 1px solid #dddee5; }
QListWidget {
    background: white;
    border: 1.5px solid #dddee5;
    border-radius: 6px;
    color: #2e2f38;
    font-size: 12px;
    outline: 0;
}
QListWidget::item { padding: 5px 8px; border-radius: 4px; }
QListWidget::item:selected { background: #eef0fb; color: #4f46e5; }
QCheckBox { color: #2e2f38; font-size: 13px; spacing: 8px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1.5px solid #dddee5;
    border-radius: 4px;
    background: white;
}
QCheckBox::indicator:checked { background: #4f46e5; border-color: #4f46e5; image: none; }
QCheckBox::indicator:hover { border-color: #4f46e5; }
QProgressBar {
    background: #eef0fb;
    border: 1.5px solid #dddee5;
    border-radius: 6px;
    height: 10px;
    text-align: center;
    font-size: 11px;
    color: #555666;
}
QProgressBar::chunk {
    background: #4f46e5;
    border-radius: 5px;
}
)qss";

static const char* DARK_STYLE = R"qss(
QMainWindow, QWidget#central { background: #1a1b26; }
QTabWidget::pane { border: none; background: transparent; }
QTabBar { background: #1f2335; border-bottom: 1px solid #414868; }
QTabBar::tab { background: transparent; color: #565f89; padding: 11px 24px;
               font-size: 13px; font-weight: 600; border: none;
               border-bottom: 3px solid transparent; margin-right: 2px; }
QTabBar::tab:selected { color: #7aa2f7; border-bottom: 3px solid #7aa2f7; }
QTabBar::tab:hover:!selected { color: #c0caf5; border-bottom: 3px solid #414868; }
QLabel { color: #c0caf5; font-size: 13px; }
QLineEdit { background: #24283b; border: 1.5px solid #414868; border-radius: 6px;
            padding: 6px 10px; font-size: 13px; color: #c0caf5; }
QLineEdit:focus { border-color: #7aa2f7; }
QLineEdit:read-only { background: #1f2335; color: #565f89; }
QComboBox { background: #24283b; border: 1.5px solid #414868; border-radius: 6px;
            padding: 6px 10px; font-size: 13px; color: #c0caf5; min-height: 28px; }
QComboBox:focus { border-color: #7aa2f7; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView { background: #24283b; border: 1.5px solid #414868;
    border-radius: 6px; selection-background-color: #2f3549;
    selection-color: #7aa2f7; padding: 4px; }
QPushButton { background: #24283b; border: 1.5px solid #414868; border-radius: 6px;
              padding: 6px 14px; font-size: 13px; color: #c0caf5; }
QPushButton:hover { background: #2f3549; border-color: #7aa2f7; color: #7aa2f7; }
QPushButton:pressed { background: #1f2335; }
QPushButton#eyeBtn { background: transparent; border: 1.5px solid #414868;
    border-radius: 6px; color: #565f89; font-size: 10px; padding: 0; }
QPushButton#eyeBtn:checked { color: #7aa2f7; border-color: #7aa2f7; }
QPushButton#copyBtn { font-size: 12px; color: #565f89; padding: 5px 10px; }
QGroupBox { background: #1f2335; border: 1.5px solid #414868; border-radius: 8px;
            margin-top: 8px; padding-top: 4px; font-size: 12px;
            font-weight: 600; color: #565f89; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left;
    padding: 0 6px; left: 12px; color: #565f89; }
QWidget#formPane { background: #1f2335; border-right: 1px solid #414868; }
QPlainTextEdit { background: #24283b; color: #c0caf5; border: 1.5px solid #414868;
    border-radius: 6px; padding: 8px; selection-background-color: #2f3549; }
QListWidget { background: #24283b; border: 1.5px solid #414868; border-radius: 6px;
              color: #c0caf5; font-size: 12px; outline: 0; }
QListWidget::item { padding: 5px 8px; border-radius: 4px; }
QListWidget::item:selected { background: #2f3549; color: #7aa2f7; }
QCheckBox { color: #c0caf5; font-size: 13px; spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1.5px solid #414868;
    border-radius: 4px; background: #24283b; }
QCheckBox::indicator:checked { background: #7aa2f7; border-color: #7aa2f7; }
QCheckBox::indicator:hover { border-color: #7aa2f7; }
QScrollArea { background: transparent; border: none; }
QScrollBar:vertical { background: #1f2335; width: 7px; border-radius: 4px; }
QScrollBar::handle:vertical { background: #414868; border-radius: 4px; min-height: 20px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QStatusBar { color: #565f89; font-size: 11px; }
QProgressBar { background: #24283b; border: 1.5px solid #414868; border-radius: 6px;
    height: 10px; text-align: center; font-size: 11px; color: #c0caf5; }
QProgressBar::chunk { background: #7aa2f7; border-radius: 5px; }
)qss";

// ── CryptografWindow ──────────────────────────────────────────────────────────
class CryptografWindow : public QMainWindow {
    Q_OBJECT

    QPlainTextEdit*        log_       = nullptr;
    Worker*                work_      = nullptr;
    QComboBox*             encModeCb_ = nullptr;   // sync with Settings default
    bool                   darkMode_  = false;
    QList<DotGridWidget*>  diagrams_;              // all dot-grid backgrounds

    void logMsg(const QString& msg) {
        const auto ts = QDateTime::currentDateTime().toString("hh:mm:ss");
        log_->appendPlainText(QStringLiteral("[%1] %2").arg(ts, msg));
    }

    void setBusy(bool busy) {
        for (auto* b : findChildren<QPushButton*>(QStringLiteral("opBtn")))
            b->setEnabled(!busy);
        statusBar()->showMessage(busy ? "Выполняется операция…" : "Готово.");
    }

    void applyTheme(bool dark) {
        darkMode_ = dark;
        setStyleSheet(dark ? DARK_STYLE : APP_STYLE);
        for (auto* w : diagrams_) w->setDark(dark);
        QSettings("Cryptograf","Cryptograf").setValue("darkMode", dark);
    }

    static QWidget* makeFormPane(QWidget* parent = nullptr) {
        auto* w = new QWidget(parent);
        w->setObjectName("formPane");
        w->setMinimumWidth(310);
        w->setMaximumWidth(440);
        w->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
        return w;
    }

    static QPushButton* makeActionBtn(const QString& text, const QString& bg,
                                      const QString& hover, const QString& dis) {
        auto* btn = new QPushButton(text);
        btn->setObjectName("opBtn");
        btn->setMinimumHeight(38);
        btn->setStyleSheet(QString(
            "QPushButton          { background:%1;color:white;border:none;border-radius:7px;"
            "                       font-weight:700;font-size:13px;padding:0 18px; }"
            "QPushButton:hover    { background:%2; }"
            "QPushButton:disabled { background:%3;color:rgba(255,255,255,0.5); }").arg(bg,hover,dis));
        return btn;
    }

    QWidget* makeEncryptTab() {

        auto* splitter = new QSplitter(Qt::Horizontal);
        splitter->setHandleWidth(1);
        splitter->setChildrenCollapsible(false);

        auto* formPane = makeFormPane();
        auto* scroll   = new QScrollArea(formPane);
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        auto* lay = new QVBoxLayout(formPane);
        lay->setContentsMargins(0, 0, 0, 0);
        lay->addWidget(scroll);

        auto* inner = new QWidget;
        auto* vlay  = new QVBoxLayout(inner);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);
        scroll->setWidget(inner);

        auto* titleLbl = new QLabel("01  Шифровать");
        titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
        vlay->addWidget(titleLbl);

        auto* form = new QFormLayout;
        form->setSpacing(10); form->setContentsMargins(0, 4, 0, 0);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addLayout(form);

        auto* typeCombo = new QComboBox;
        typeCombo->addItem("Файл");
        typeCombo->addItem("Папка");
        form->addRow("Тип:", typeCombo);

        const int defMode = QSettings("Cryptograf","Cryptograf").value("defaultMode", 4).toInt();
        auto* combo = new QComboBox;
        for (const auto& m : MODES) combo->addItem(m.name);
        combo->setCurrentIndex(defMode);
        encModeCb_ = combo;
        form->addRow("Режим:", combo);

        auto* desc = new QLabel(MODES[4].desc);
        desc->setWordWrap(true);
        desc->setStyleSheet("color:#7f8090;font-size:11px;padding:2px 0;");
        connect(combo, &QComboBox::currentIndexChanged, [desc](int i) {
            if (i >= 0 && i < MODE_COUNT) desc->setText(MODES[i].desc);
        });
        form->addRow("", desc);

        // Input row (manual so browse button can switch file/folder mode)
        auto* inRow = new QWidget(inner);
        auto* inH   = new QHBoxLayout(inRow);
        inH->setContentsMargins(0,0,0,0); inH->setSpacing(6);
        auto* inEdit = new DropEdit(inRow);
        inEdit->setPlaceholderText("Перетащите файл или нажмите «Обзор…»");
        auto* inBtn  = new QPushButton("Обзор…", inRow);
        inBtn->setFixedWidth(76);
        inH->addWidget(inEdit); inH->addWidget(inBtn);
        auto* inLabel = new QLabel("Входной файл:");
        form->addRow(inLabel, inRow);

        connect(inBtn, &QPushButton::clicked, [inEdit, typeCombo, inner]() {
            const bool isDir = typeCombo->currentIndex() == 1;
            QString p = isDir
                ? QFileDialog::getExistingDirectory(inner, "Выбрать папку для шифрования")
                : QFileDialog::getOpenFileName(inner, "Открыть файл");
            if (!p.isEmpty()) inEdit->setText(p);
        });
        connect(typeCombo, &QComboBox::currentIndexChanged, [inEdit, inLabel](int i) {
            const bool isDir = i == 1;
            inLabel->setText(isDir ? "Входная папка:" : "Входной файл:");
            inEdit->setPlaceholderText(isDir ? "Перетащите папку или нажмите «Обзор…»"
                                             : "Перетащите файл или нажмите «Обзор…»");
        });

        DropEdit* outEdit;
        form->addRow("Выходной файл:", makeFileRow(outEdit, false, inner));
        connect(inEdit, &QLineEdit::textChanged, [outEdit](const QString& t) {
            if (outEdit->text().isEmpty() && !t.isEmpty()) outEdit->setText(t + ".enc");
        });

        QLineEdit *pw1, *pw2;
        form->addRow("Пароль:", makePwRow(pw1, "Введите пароль…", inner));

        // ── Strength indicator ────────────────────────────────────────────────
        static const char* STRENGTH_COLORS[] =
            { "", "#ef4444", "#f97316", "#eab308", "#22c55e" };
        static const char* STRENGTH_LABELS[] =
            { "", "Очень слабый", "Слабый", "Средний", "Надёжный" };

        auto* strRow = new QWidget(inner);
        auto* strH   = new QHBoxLayout(strRow);
        strH->setContentsMargins(0, 3, 0, 3);
        strH->setSpacing(5);

        std::array<QLabel*, 4> segs;
        for (int i = 0; i < 4; ++i) {
            segs[i] = new QLabel(strRow);
            segs[i]->setFixedSize(36, 5);
            segs[i]->setStyleSheet("background:#e0e1eb; border-radius:2px;");
            strH->addWidget(segs[i]);
        }
        auto* strText = new QLabel("", strRow);
        strText->setStyleSheet("color:#7f8090; font-size:11px; margin-left:2px;");
        strH->addWidget(strText, 1);
        form->addRow("Надёжность:", strRow);

        connect(pw1, &QLineEdit::textChanged, [segs, strText](const QString& pw) {
            const int sc = calcStrength(pw);
            for (int i = 0; i < 4; ++i)
                segs[i]->setStyleSheet(i < sc
                    ? QString("background:%1; border-radius:2px;").arg(STRENGTH_COLORS[sc])
                    : "background:#e0e1eb; border-radius:2px;");
            strText->setText(pw.isEmpty() ? "" : STRENGTH_LABELS[sc]);
            strText->setStyleSheet(sc > 0
                ? QString("color:%1; font-size:11px; font-weight:600; margin-left:2px;")
                      .arg(STRENGTH_COLORS[sc])
                : "color:#7f8090; font-size:11px; margin-left:2px;");
        });
        // ─────────────────────────────────────────────────────────────────────

        form->addRow("Подтверждение:", makePwRow(pw2, "Повторите пароль…", inner));

        auto* btn = makeActionBtn("  Зашифровать", "#4f46e5", "#4338ca", "#a5b4fc");
        form->addRow("", btn);

        auto* progBar = new QProgressBar;
        progBar->setRange(0, 100);
        progBar->setValue(0);
        progBar->setVisible(false);
        progBar->setTextVisible(false);
        form->addRow("", progBar);

        auto* resultBox = new QGroupBox("Результат шифрования");
        resultBox->setVisible(false);
        auto* rform = new QFormLayout(resultBox);
        rform->setSpacing(8); rform->setContentsMargins(12, 8, 12, 8);
        rform->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        rform->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

        auto* ctDisplay = new QLineEdit;
        ctDisplay->setReadOnly(true); ctDisplay->setFont(monoFont(9));
        auto getCTHex = [outEdit]() -> QString {
            auto p = parseEncFile(outEdit->text().trimmed());
            return p ? QString::fromLatin1(p->ciphertext.toHex()) : QString{};
        };
        rform->addRow("Шифртекст:", makeCopyRow(ctDisplay, getCTHex, resultBox));

        auto* tagLabel   = new QLabel("Имитовставка:");
        auto* tagDisplay = new QLineEdit;
        tagDisplay->setReadOnly(true); tagDisplay->setFont(monoFont(9));
        auto getTagHex = [tagDisplay]() { return tagDisplay->text(); };
        rform->addRow(tagLabel, makeCopyRow(tagDisplay, getTagHex, resultBox));
        vlay->addWidget(resultBox);
        vlay->addStretch(1);

        connect(btn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = inEdit->text().trimmed();
            const QString out = outEdit->text().trimmed();
            const QString p1  = pw1->text();
            const QString p2  = pw2->text();
            const int     mi  = combo->currentIndex();
            const bool isDir  = typeCombo->currentIndex() == 1;
            if (in.isEmpty())  { QMessageBox::warning(this,"Ошибка",
                                     isDir ? "Укажите входную папку." : "Укажите входной файл."); return; }
            if (out.isEmpty()) { QMessageBox::warning(this,"Ошибка","Укажите выходной файл."); return; }
            if (p1.isEmpty())  { QMessageBox::warning(this,"Ошибка","Пароль не должен быть пустым."); return; }
            if (p1 != p2)      { QMessageBox::warning(this,"Ошибка","Пароли не совпадают."); return; }
            if (isDir) {
                if (!QDir(in).exists()) { QMessageBox::warning(this,"Ошибка","Папка не найдена."); return; }
            } else {
                if (!QFile::exists(in)) { QMessageBox::warning(this,"Ошибка","Входной файл не найден."); return; }
            }
            if (QFile::exists(out)) {
                if (QMessageBox::question(this,"Файл существует",
                        QString("'%1' уже существует.\nПерезаписать?").arg(out))
                        != QMessageBox::Yes) return;
                QFile::remove(out);
            }
            resultBox->setVisible(false);
            progBar->setValue(0);
            progBar->setVisible(true);
            setBusy(true);
            logMsg(QString("Шифрование [%1]: %2  →  %3").arg(combo->currentText(), in, out));
            work_ = new Worker;
            const auto mode = MODES[mi].mode;
            if (isDir) {
                work_->task = [i=in.toStdString(),o=out.toStdString(),
                                p=p1.toStdString(),mode,w=work_]() {
                    crypto::encrypt_dir(i, o, p, mode, [w](int64_t d, int64_t t) {
                        w->reportProgress(d, t);
                    });
                };
            } else {
                work_->task = [i=in.toStdString(),o=out.toStdString(),
                                p=p1.toStdString(),mode,w=work_]() {
                    crypto::encrypt_file(i, o, p, mode, [w](int64_t d, int64_t t) {
                        w->reportProgress(d, t);
                    });
                };
            }
            connect(work_, &Worker::progress, progBar, [progBar](qint64 d, qint64 t) {
                if (t > 0) progBar->setValue(static_cast<int>(d * 100 / t));
            }, Qt::QueuedConnection);
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                progBar->setVisible(false);
                setBusy(false);
                if (ok) {
                    auto parts = parseEncFile(out);
                    if (parts && !parts->is_folder) {
                        constexpr int PREV = 24;
                        const auto& ct = parts->ciphertext;
                        ctDisplay->setText(ct.size() <= PREV
                            ? QString::fromLatin1(ct.toHex())
                            : QString::fromLatin1(ct.left(PREV).toHex()) + QString("… (%1B)").arg(ct.size()));
                        tagLabel->setText(parts->is_aead ? "Имитовставка:" : "HMAC-SHA256:");
                        tagDisplay->setText(QString::fromLatin1(parts->tag.toHex()));
                        resultBox->setVisible(true);
                    }
                    logMsg(QString("✓ Готово. Шифртекст: %1 байт, тег: %2 байт")
                           .arg(parts?parts->ciphertext.size():0).arg(parts?parts->tag.size():0));
                } else {
                    QFile::remove(out);
                    logMsg("✗ Ошибка: " + err);
                    QMessageBox::critical(this,"Ошибка шифрования",err);
                }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        auto* diagram = new EncryptDiagramWidget;
        connect(combo, &QComboBox::currentIndexChanged, [diagram](int i) {
            if (i >= 0 && i < 9)
                diagram->setMode(static_cast<crypto::Mode>(i));
        });
        diagram->setMode(MODES[4].mode); // CTR default

        splitter->addWidget(formPane);
        splitter->addWidget(wrapDiagram(diagram, splitter, &diagrams_));
        splitter->setStretchFactor(0, 0);
        splitter->setStretchFactor(1, 1);
        return splitter;
    }

    QWidget* makeDecryptTab() {
        auto* splitter = new QSplitter(Qt::Horizontal);
        splitter->setHandleWidth(1);
        splitter->setChildrenCollapsible(false);

        auto* formPane = makeFormPane();
        auto* vlay     = new QVBoxLayout(formPane);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        auto* titleLbl = new QLabel("02  Расшифровать");
        titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
        vlay->addWidget(titleLbl);

        auto* form = new QFormLayout;
        form->setSpacing(10); form->setContentsMargins(0, 4, 0, 0);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addLayout(form);

        DropEdit* inEdit;
        form->addRow("Зашифрованный файл:", makeFileRow(inEdit, true, formPane));

        // Output row (manual — label and picker switch on folder-archive detection)
        auto* outRow = new QWidget(formPane);
        auto* outH   = new QHBoxLayout(outRow);
        outH->setContentsMargins(0,0,0,0); outH->setSpacing(6);
        auto* outEdit = new DropEdit(outRow);
        outEdit->setPlaceholderText("Путь к выходному файлу…");
        auto* outBtn  = new QPushButton("Обзор…", outRow);
        outBtn->setFixedWidth(76);
        outH->addWidget(outEdit); outH->addWidget(outBtn);
        auto* outLabel = new QLabel("Выходной файл:");
        form->addRow(outLabel, outRow);

        connect(outBtn, &QPushButton::clicked, [outEdit, inEdit, formPane]() {
            const bool isFolder = crypto::is_dir_archive(inEdit->text().trimmed().toStdString());
            QString p = isFolder
                ? QFileDialog::getExistingDirectory(formPane, "Выбрать папку назначения")
                : QFileDialog::getSaveFileName(formPane, "Сохранить как");
            if (!p.isEmpty()) outEdit->setText(p);
        });

        connect(inEdit, &QLineEdit::textChanged, [outEdit, outLabel](const QString& t) {
            if (t.isEmpty()) return;
            const bool isFolder = crypto::is_dir_archive(t.trimmed().toStdString());
            outLabel->setText(isFolder ? "Папка назначения:" : "Выходной файл:");
            outEdit->setPlaceholderText(isFolder ? "Путь к папке…" : "Путь к выходному файлу…");
            if (outEdit->text().isEmpty()) {
                QString o = t.trimmed();
                if (o.endsWith(".enc", Qt::CaseInsensitive)) o.chop(4); else o += ".dec";
                outEdit->setText(o);
            }
        });

        QLineEdit* pw;
        form->addRow("Пароль:", makePwRow(pw, "Введите пароль…", formPane));
        auto* btn = makeActionBtn("  Расшифровать", "#16a34a", "#15803d", "#86efac");
        form->addRow("", btn);

        auto* progBar = new QProgressBar;
        progBar->setRange(0, 100);
        progBar->setValue(0);
        progBar->setVisible(false);
        progBar->setTextVisible(false);
        form->addRow("", progBar);

        vlay->addStretch(1);

        connect(btn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = inEdit->text().trimmed();
            const QString out = outEdit->text().trimmed();
            const QString p   = pw->text();
            if (in.isEmpty())       { QMessageBox::warning(this,"Ошибка","Укажите файл для расшифрования."); return; }
            if (out.isEmpty())      { QMessageBox::warning(this,"Ошибка","Укажите выходной путь."); return; }
            if (p.isEmpty())        { QMessageBox::warning(this,"Ошибка","Пароль не должен быть пустым."); return; }
            if (!QFile::exists(in)) { QMessageBox::warning(this,"Ошибка","Входной файл не найден."); return; }

            const bool isFolder = crypto::is_dir_archive(in.toStdString());
            if (!isFolder) {
                if (QFile::exists(out)) {
                    if (QMessageBox::question(this,"Файл существует",
                            QString("'%1' уже существует.\nПерезаписать?").arg(out))
                            != QMessageBox::Yes) return;
                    QFile::remove(out);
                }
            }

            progBar->setValue(0);
            progBar->setVisible(true);
            setBusy(true);
            logMsg(QString("Расшифрование: %1  →  %2").arg(in, out));
            work_ = new Worker;
            if (isFolder) {
                work_->task = [i=in.toStdString(),o=out.toStdString(),
                                pw=p.toStdString(),w=work_]() {
                    crypto::decrypt_dir(i, o, pw, [w](int64_t d, int64_t t) {
                        w->reportProgress(d, t);
                    });
                };
            } else {
                work_->task = [i=in.toStdString(),o=out.toStdString(),
                                pw=p.toStdString(),w=work_]() {
                    crypto::decrypt_file(i, o, pw, [w](int64_t d, int64_t t) {
                        w->reportProgress(d, t);
                    });
                };
            }
            connect(work_, &Worker::progress, progBar, [progBar](qint64 d, qint64 t) {
                if (t > 0) progBar->setValue(static_cast<int>(d * 100 / t));
            }, Qt::QueuedConnection);
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                progBar->setVisible(false);
                setBusy(false);
                if (ok) {
                    if (isFolder)
                        logMsg(QString("✓ Готово. Папка: %1").arg(out));
                    else
                        logMsg(QString("✓ Готово. Размер: %1 байт").arg(QFileInfo(out).size()));
                } else {
                    if (!isFolder) QFile::remove(out);
                    logMsg("✗ Ошибка: "+err);
                    QMessageBox::critical(this,"Ошибка расшифрования",err);
                }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        splitter->addWidget(formPane);
        splitter->addWidget(wrapDiagram(new StaticSvgDiagram(":/diagrams/decrypt.svg"), splitter, &diagrams_));
        splitter->setStretchFactor(0, 0);
        splitter->setStretchFactor(1, 1);
        return splitter;
    }

    QWidget* makeSignTab() {
        auto* splitter = new QSplitter(Qt::Horizontal);
        splitter->setHandleWidth(1);
        splitter->setChildrenCollapsible(false);

        auto* formPane = makeFormPane();
        auto* scroll   = new QScrollArea(formPane);
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        auto* fpLay = new QVBoxLayout(formPane);
        fpLay->setContentsMargins(0, 0, 0, 0);
        fpLay->addWidget(scroll);

        auto* inner = new QWidget;
        auto* vlay  = new QVBoxLayout(inner);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);
        scroll->setWidget(inner);

        auto* titleLbl = new QLabel("03  Подпись");
        titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
        vlay->addWidget(titleLbl);

        // Key gen
        auto* keyBox  = new QGroupBox("Генерация ключевой пары (ECDSA P-256)");
        auto* keyForm = new QFormLayout(keyBox);
        keyForm->setSpacing(8); keyForm->setContentsMargins(12, 8, 12, 8);
        keyForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        keyForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        DropEdit *privEdit, *pubEdit;
        keyForm->addRow("Закрытый ключ:", makeFileRow(privEdit, false, inner));
        keyForm->addRow("Открытый ключ:", makeFileRow(pubEdit,  false, inner));
        auto* keyBtn = makeActionBtn("  Сгенерировать ключи", "#7c3aed", "#6d28d9", "#c4b5fd");
        keyForm->addRow("", keyBtn);
        vlay->addWidget(keyBox);

        connect(keyBtn, &QPushButton::clicked, this, [=, this]() {
            const QString priv = privEdit->text().trimmed();
            const QString pub  = pubEdit->text().trimmed();
            if (priv.isEmpty()) { QMessageBox::warning(this,"Ошибка","Укажите путь для закрытого ключа."); return; }
            if (pub.isEmpty())  { QMessageBox::warning(this,"Ошибка","Укажите путь для открытого ключа."); return; }
            setBusy(true); logMsg("Генерация ключей ECDSA P-256…");
            work_ = new Worker;
            work_->task = [p=priv.toStdString(),q=pub.toStdString()]() { crypto::generate_ec_keypair(p,q); };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) logMsg("✓ Ключи сохранены: " + priv + " / " + pub);
                else  { logMsg("✗ "+err); QMessageBox::critical(this,"Ошибка",err); }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        // Sign
        auto* signBox  = new QGroupBox("Подписать файл");
        auto* signForm = new QFormLayout(signBox);
        signForm->setSpacing(8); signForm->setContentsMargins(12, 8, 12, 8);
        signForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        signForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        DropEdit *sInEdit, *sKeyEdit, *sSigEdit;
        signForm->addRow("Файл:",          makeFileRow(sInEdit,  true,  inner));
        signForm->addRow("Закрытый ключ:", makeFileRow(sKeyEdit, true,  inner));
        signForm->addRow("Файл подписи:",  makeFileRow(sSigEdit, false, inner));
        connect(sInEdit, &QLineEdit::textChanged, [sSigEdit](const QString& t) {
            if (sSigEdit->text().isEmpty() && !t.isEmpty()) sSigEdit->setText(t + ".sig");
        });
        auto* signBtn = makeActionBtn("  Подписать", "#0369a1", "#075985", "#7dd3fc");
        signForm->addRow("", signBtn);
        vlay->addWidget(signBox);

        connect(signBtn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = sInEdit->text().trimmed();
            const QString key = sKeyEdit->text().trimmed();
            const QString sig = sSigEdit->text().trimmed();
            if (in.isEmpty())        { QMessageBox::warning(this,"Ошибка","Укажите подписываемый файл."); return; }
            if (key.isEmpty())       { QMessageBox::warning(this,"Ошибка","Укажите файл закрытого ключа."); return; }
            if (sig.isEmpty())       { QMessageBox::warning(this,"Ошибка","Укажите путь для подписи."); return; }
            if (!QFile::exists(in))  { QMessageBox::warning(this,"Ошибка","Файл не найден."); return; }
            if (!QFile::exists(key)) { QMessageBox::warning(this,"Ошибка","Ключ не найден."); return; }
            setBusy(true); logMsg("Подпись файла: " + in);
            work_ = new Worker;
            work_->task = [i=in.toStdString(),k=key.toStdString(),s=sig.toStdString()]() { crypto::sign_file(i,k,s); };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) logMsg("✓ Подпись записана: " + sig);
                else  { logMsg("✗ "+err); QMessageBox::critical(this,"Ошибка подписи",err); }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        // Verify
        auto* verBox  = new QGroupBox("Проверить подпись");
        auto* verForm = new QFormLayout(verBox);
        verForm->setSpacing(8); verForm->setContentsMargins(12, 8, 12, 8);
        verForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        verForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        DropEdit *vInEdit, *vSigEdit, *vKeyEdit;
        verForm->addRow("Файл:",           makeFileRow(vInEdit,  true, inner));
        verForm->addRow("Файл подписи:",  makeFileRow(vSigEdit, true, inner));
        verForm->addRow("Открытый ключ:", makeFileRow(vKeyEdit, true, inner));
        auto* verBtn = makeActionBtn("  Проверить подпись", "#16a34a", "#15803d", "#86efac");
        verForm->addRow("", verBtn);
        vlay->addWidget(verBox);
        vlay->addStretch(1);

        connect(verBtn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = vInEdit->text().trimmed();
            const QString sig = vSigEdit->text().trimmed();
            const QString key = vKeyEdit->text().trimmed();
            if (in.isEmpty())        { QMessageBox::warning(this,"Ошибка","Укажите проверяемый файл."); return; }
            if (sig.isEmpty())       { QMessageBox::warning(this,"Ошибка","Укажите файл подписи."); return; }
            if (key.isEmpty())       { QMessageBox::warning(this,"Ошибка","Укажите файл открытого ключа."); return; }
            if (!QFile::exists(in))  { QMessageBox::warning(this,"Ошибка","Файл не найден."); return; }
            if (!QFile::exists(sig)) { QMessageBox::warning(this,"Ошибка","Файл подписи не найден."); return; }
            if (!QFile::exists(key)) { QMessageBox::warning(this,"Ошибка","Ключ не найден."); return; }
            setBusy(true); logMsg("Проверка подписи: " + in);
            work_ = new Worker;
            auto result = std::make_shared<bool>(false);
            work_->task = [i=in.toStdString(),s=sig.toStdString(),k=key.toStdString(),result]() {
                *result = crypto::verify_file(i,s,k);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) {
                    if (*result) {
                        logMsg("✓ Подпись ВЕРНА. Файл не изменён.");
                        QMessageBox::information(this,"Результат проверки",
                            "Подпись верна.\nФайл не был изменён после подписания.");
                    } else {
                        logMsg("✗ Подпись НЕДЕЙСТВИТЕЛЬНА.");
                        QMessageBox::critical(this,"Результат проверки",
                            "Подпись недействительна!\nФайл мог быть изменён или используется другой ключ.");
                    }
                } else { logMsg("✗ "+err); QMessageBox::critical(this,"Ошибка проверки",err); }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        splitter->addWidget(formPane);
        splitter->addWidget(wrapDiagram(new StaticSvgDiagram(":/diagrams/sign.svg"), splitter, &diagrams_));
        splitter->setStretchFactor(0, 0);
        splitter->setStretchFactor(1, 1);
        return splitter;
    }

    QWidget* makeInfoTab() {
        auto* splitter = new QSplitter(Qt::Horizontal);
        splitter->setHandleWidth(1);
        splitter->setChildrenCollapsible(false);

        auto* formPane = makeFormPane();
        auto* vlay     = new QVBoxLayout(formPane);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        auto* titleLbl = new QLabel("04  Информация");
        titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
        vlay->addWidget(titleLbl);
        auto* subLbl = new QLabel("Разбор заголовка и метаданных .enc файла");
        subLbl->setStyleSheet("font-size:12px;color:#7f8090;");
        vlay->addWidget(subLbl);

        auto* row = new QWidget;
        auto* h   = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, 0); h->setSpacing(8);
        auto* lbl = new QLabel("Файл:");
        lbl->setFixedWidth(44);
        auto* fileEdit  = new DropEdit;
        fileEdit->setPlaceholderText("Перетащите или выберите .enc файл…");
        auto* browseBtn = new QPushButton("Обзор…");
        browseBtn->setFixedWidth(76);
        h->addWidget(lbl); h->addWidget(fileEdit); h->addWidget(browseBtn);
        vlay->addWidget(row);

        connect(browseBtn, &QPushButton::clicked, [fileEdit, this]() {
            auto p = QFileDialog::getOpenFileName(this, "Открыть зашифрованный файл",
                         {}, "Зашифрованные файлы (*.enc);;Все файлы (*)");
            if (!p.isEmpty()) fileEdit->setText(p);
        });

        auto* view = new QPlainTextEdit;
        view->setReadOnly(true);
        view->setFont(monoFont(10));
        view->setPlaceholderText("Информация о файле появится здесь…");
        view->setStyleSheet(
            "QPlainTextEdit { background:#f7f8fb;border:1.5px solid #dddee5;"
            "                 border-radius:6px;padding:8px;color:#2e2f38; }");
        vlay->addWidget(view, 1);

        connect(fileEdit, &QLineEdit::textChanged, [view](const QString& t) {
            view->setPlainText(t.isEmpty() ? QString{} : buildFileInfo(t));
        });

        splitter->addWidget(formPane);
        splitter->addWidget(wrapDiagram(new StaticSvgDiagram(":/diagrams/info.svg"), splitter, &diagrams_));
        splitter->setStretchFactor(0, 0);
        splitter->setStretchFactor(1, 1);
        return splitter;
    }

    // ── 05  Пакетное шифрование ───────────────────────────────────────────────
    QWidget* makeBatchTab() {
        auto* w    = new QWidget;
        auto* vlay = new QVBoxLayout(w);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        auto* titleLbl = new QLabel("05  Пакетное шифрование");
        titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
        vlay->addWidget(titleLbl);
        auto* subLbl = new QLabel("Зашифруйте или расшифруйте несколько файлов за один раз");
        subLbl->setStyleSheet("font-size:12px;color:#7f8090;");
        vlay->addWidget(subLbl);

        // File list
        auto* fileList = new QListWidget;
        fileList->setSelectionMode(QAbstractItemView::ExtendedSelection);
        fileList->setMinimumHeight(180);
        vlay->addWidget(fileList, 1);

        // List control buttons
        auto* listBtnRow = new QWidget;
        auto* listH = new QHBoxLayout(listBtnRow);
        listH->setContentsMargins(0,0,0,0); listH->setSpacing(8);
        auto* addBtn = new QPushButton("＋  Добавить файлы");
        auto* delBtn = new QPushButton("－  Удалить выбранные");
        auto* clrBtn = new QPushButton("Очистить список");
        listH->addWidget(addBtn); listH->addWidget(delBtn); listH->addWidget(clrBtn);
        listH->addStretch(1);
        vlay->addWidget(listBtnRow);

        connect(addBtn, &QPushButton::clicked, [fileList, w]() {
            const auto files = QFileDialog::getOpenFileNames(w, "Выбрать файлы");
            for (const auto& f : files) {
                // Avoid duplicates
                bool dup = false;
                for (int i = 0; i < fileList->count(); ++i)
                    if (fileList->item(i)->data(Qt::UserRole).toString() == f) { dup=true; break; }
                if (!dup) {
                    auto* item = new QListWidgetItem(QFileInfo(f).fileName());
                    item->setData(Qt::UserRole, f);
                    item->setToolTip(f);
                    fileList->addItem(item);
                }
            }
        });
        connect(delBtn, &QPushButton::clicked, [fileList]() {
            for (auto* item : fileList->selectedItems()) delete item;
        });
        connect(clrBtn, &QPushButton::clicked, [fileList]() { fileList->clear(); });

        // Mode + password form
        auto* form = new QFormLayout;
        form->setSpacing(10); form->setContentsMargins(0,8,0,0);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addLayout(form);

        const int defMode = QSettings("Cryptograf","Cryptograf").value("defaultMode",4).toInt();
        auto* modeCombo = new QComboBox;
        for (const auto& m : MODES) modeCombo->addItem(m.name);
        modeCombo->setCurrentIndex(defMode);
        form->addRow("Режим (шифр.):", modeCombo);

        QLineEdit* pw;
        form->addRow("Пароль:", makePwRow(pw, "Пароль для всех файлов…", w));

        // Action buttons + progress
        auto* actRow = new QWidget;
        auto* actH = new QHBoxLayout(actRow);
        actH->setContentsMargins(0,0,0,0); actH->setSpacing(8);
        auto* encBtn = makeActionBtn("  Зашифровать все", "#4f46e5", "#4338ca", "#a5b4fc");
        auto* decBtn = makeActionBtn("  Расшифровать все", "#16a34a", "#15803d", "#86efac");
        actH->addWidget(encBtn); actH->addWidget(decBtn); actH->addStretch(1);
        form->addRow("", actRow);

        auto* progBar = new QProgressBar;
        progBar->setRange(0, 1); progBar->setValue(0);
        progBar->setVisible(false); progBar->setTextVisible(false);
        auto* statusLbl = new QLabel("");
        statusLbl->setStyleSheet("color:#7f8090; font-size:12px;");
        form->addRow("", progBar);
        form->addRow("", statusLbl);

        // Helper: run batch in worker
        auto runBatch = [=, this](bool encrypt) {
            if (fileList->count() == 0) {
                QMessageBox::warning(this,"Ошибка","Список файлов пуст."); return;
            }
            if (pw->text().isEmpty()) {
                QMessageBox::warning(this,"Ошибка","Введите пароль."); return;
            }
            QStringList files;
            for (int i = 0; i < fileList->count(); ++i)
                files << fileList->item(i)->data(Qt::UserRole).toString();

            // Reset list visuals
            for (int i = 0; i < fileList->count(); ++i) {
                fileList->item(i)->setForeground(QApplication::palette().text());
                fileList->item(i)->setText(QFileInfo(files[i]).fileName());
            }

            const int n = files.size();
            progBar->setRange(0, n); progBar->setValue(0); progBar->setVisible(true);
            statusLbl->setText(QString("Обработка 0 / %1…").arg(n));
            setBusy(true);
            logMsg(QString("Пакет: %1 файл(ов), %2").arg(n).arg(encrypt?"шифрование":"расшифрование"));

            const auto mode = MODES[modeCombo->currentIndex()].mode;
            const auto password = pw->text();

            struct Res { bool ok; QString err; };
            auto results = std::make_shared<QVector<Res>>(n);

            work_ = new Worker;
            work_->task = [files, password, mode, encrypt, results, w=work_]() {
                for (int i = 0; i < files.size(); ++i) {
                    (*results)[i] = {false, {}};
                    try {
                        const auto in = files[i].toStdString();
                        std::string out;
                        if (encrypt) {
                            out = in + ".enc";
                            if (std::filesystem::exists(out))
                                throw std::runtime_error("выходной файл уже существует");
                            crypto::encrypt_file(in, out, password.toStdString(), mode);
                        } else {
                            auto o = files[i];
                            if (o.endsWith(".enc", Qt::CaseInsensitive)) o.chop(4); else o += ".dec";
                            out = o.toStdString();
                            if (std::filesystem::exists(out))
                                throw std::runtime_error("выходной файл уже существует");
                            crypto::decrypt_file(in, out, password.toStdString());
                        }
                        (*results)[i] = {true, {}};
                    } catch (const std::exception& e) {
                        (*results)[i] = {false, QString::fromStdString(e.what())};
                    }
                    w->reportProgress(i + 1, files.size());
                }
            };

            connect(work_, &Worker::progress, this,
                    [=, this](qint64 cur, qint64 tot) {
                        const int i = static_cast<int>(cur) - 1;
                        if (i >= 0 && i < fileList->count()) {
                            const auto& r = (*results)[i];
                            auto* item = fileList->item(i);
                            if (r.ok) {
                                item->setForeground(QColor("#22c55e"));
                                item->setText("✓ " + QFileInfo(files[i]).fileName());
                            } else {
                                item->setForeground(QColor("#ef4444"));
                                item->setText("✗ " + QFileInfo(files[i]).fileName()
                                              + "  —  " + r.err);
                            }
                        }
                        progBar->setValue(static_cast<int>(cur));
                        statusLbl->setText(QString("Обработано: %1 / %2").arg(cur).arg(tot));
                    }, Qt::QueuedConnection);

            connect(work_, &Worker::done, this, [=, this](bool, QString) {
                progBar->setVisible(false);
                setBusy(false);
                int ok = 0, fail = 0;
                for (const auto& r : *results) r.ok ? ++ok : ++fail;
                statusLbl->setText(QString("Завершено: %1 ОК, %2 ошибок").arg(ok).arg(fail));
                logMsg(QString("✓ Пакет завершён: %1 ОК, %2 ошибок").arg(ok).arg(fail));
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);

            work_->start();
        };

        connect(encBtn, &QPushButton::clicked, this, [runBatch]{ runBatch(true);  });
        connect(decBtn, &QPushButton::clicked, this, [runBatch]{ runBatch(false); });

        return w;
    }

    // ── 06  Зашифрованные заметки ─────────────────────────────────────────────
    QWidget* makeNotesTab() {
        auto* w    = new QWidget;
        auto* vlay = new QVBoxLayout(w);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        auto* titleLbl = new QLabel("06  Заметки");
        titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
        vlay->addWidget(titleLbl);
        auto* subLbl = new QLabel("Текст шифруется напрямую — без временных файлов на диске");
        subLbl->setStyleSheet("font-size:12px;color:#7f8090;");
        vlay->addWidget(subLbl);

        auto* editor = new QPlainTextEdit;
        editor->setPlaceholderText("Введите текст заметки…");
        editor->setFont(monoFont(11));
        editor->setStyleSheet(
            "QPlainTextEdit { background:white; border:1.5px solid #dddee5;"
            " border-radius:6px; padding:8px; }");
        vlay->addWidget(editor, 1);

        auto* form = new QFormLayout;
        form->setSpacing(10); form->setContentsMargins(0,6,0,0);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addLayout(form);

        const int defMode = QSettings("Cryptograf","Cryptograf").value("defaultMode",4).toInt();
        auto* modeCombo = new QComboBox;
        for (const auto& m : MODES) modeCombo->addItem(m.name);
        modeCombo->setCurrentIndex(defMode);
        form->addRow("Режим:", modeCombo);

        QLineEdit* pw;
        form->addRow("Пароль:", makePwRow(pw, "Пароль заметки…", w));

        auto* btnRow = new QWidget;
        auto* btnH   = new QHBoxLayout(btnRow);
        btnH->setContentsMargins(0,0,0,0); btnH->setSpacing(8);
        auto* saveBtn  = makeActionBtn("  Сохранить", "#4f46e5", "#4338ca", "#a5b4fc");
        auto* loadBtn  = makeActionBtn("  Открыть",   "#16a34a", "#15803d", "#86efac");
        auto* clearBtn = new QPushButton("Очистить");
        btnH->addWidget(saveBtn); btnH->addWidget(loadBtn); btnH->addWidget(clearBtn);
        btnH->addStretch(1);
        form->addRow("", btnRow);

        auto* statusLbl = new QLabel("");
        statusLbl->setStyleSheet("color:#7f8090; font-size:12px;");
        form->addRow("", statusLbl);

        // Save: encrypt editor content → .enc file (via temp file)
        connect(saveBtn, &QPushButton::clicked, this, [=, this]() {
            const QString text = editor->toPlainText();
            const QString p    = pw->text();
            if (text.trimmed().isEmpty()) { QMessageBox::warning(this,"Ошибка","Заметка пуста."); return; }
            if (p.isEmpty())              { QMessageBox::warning(this,"Ошибка","Введите пароль."); return; }
            QString outPath = QFileDialog::getSaveFileName(this, "Сохранить заметку", {},
                                "Зашифрованные заметки (*.enc);;Все файлы (*)");
            if (outPath.isEmpty()) return;
            if (!outPath.endsWith(".enc", Qt::CaseInsensitive)) outPath += ".enc";
            if (QFile::exists(outPath)) QFile::remove(outPath);

            const auto mode = MODES[modeCombo->currentIndex()].mode;
            setBusy(true); statusLbl->setText("Шифрование…");
            work_ = new Worker;
            work_->task = [text, o=outPath.toStdString(), p=p.toStdString(), mode]() {
                const QString tmp = QDir::tempPath() + "/cg_note.tmp";
                {
                    QFile f(tmp);
                    if (!f.open(QIODevice::WriteOnly))
                        throw std::runtime_error("Не удалось создать временный файл");
                    QTextStream(&f) << text;
                }
                try {
                    crypto::encrypt_file(tmp.toStdString(), o, p, mode);
                } catch (...) { QFile::remove(tmp); throw; }
                QFile::remove(tmp);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                statusLbl->setText(ok ? "✓ Заметка сохранена: " + outPath : "✗ " + err);
                if (!ok) { QFile::remove(outPath); QMessageBox::critical(this,"Ошибка",err); }
                else logMsg("✓ Заметка зашифрована: " + outPath);
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        // Load: decrypt .enc → show in editor
        connect(loadBtn, &QPushButton::clicked, this, [=, this]() {
            const QString p = pw->text();
            if (p.isEmpty()) { QMessageBox::warning(this,"Ошибка","Введите пароль."); return; }
            QString inPath = QFileDialog::getOpenFileName(this, "Открыть заметку", {},
                               "Зашифрованные заметки (*.enc);;Все файлы (*)");
            if (inPath.isEmpty()) return;

            setBusy(true); statusLbl->setText("Расшифрование…");
            auto textResult = std::make_shared<QString>();
            work_ = new Worker;
            work_->task = [i=inPath.toStdString(), p=p.toStdString(), textResult]() {
                const QString tmp = QDir::tempPath() + "/cg_note.tmp";
                QFile::remove(tmp);
                crypto::decrypt_file(i, tmp.toStdString(), p);
                QFile f(tmp);
                if (!f.open(QIODevice::ReadOnly))
                    throw std::runtime_error("Не удалось прочитать временный файл");
                *textResult = QTextStream(&f).readAll();
                f.close();
                QFile::remove(tmp);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) {
                    editor->setPlainText(*textResult);
                    statusLbl->setText("✓ Загружено из: " + inPath);
                    logMsg("✓ Заметка расшифрована: " + inPath);
                } else {
                    statusLbl->setText("✗ " + err);
                    QMessageBox::critical(this,"Ошибка расшифрования",err);
                }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        connect(clearBtn, &QPushButton::clicked, [editor, statusLbl]() {
            editor->clear(); statusLbl->clear();
        });

        return w;
    }

    // ── 07  Настройки ─────────────────────────────────────────────────────────
    QWidget* makeSettingsTab() {
        auto* w    = new QWidget;
        auto* vlay = new QVBoxLayout(w);
        vlay->setContentsMargins(40, 28, 40, 28);
        vlay->setSpacing(0);

        auto* titleLbl = new QLabel("07  Настройки");
        titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;margin-bottom:4px;");
        vlay->addWidget(titleLbl);

        auto* box  = new QGroupBox("Параметры приложения");
        auto* form = new QFormLayout(box);
        form->setSpacing(14); form->setContentsMargins(20,16,20,16);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addWidget(box);

        // Default mode
        QSettings s("Cryptograf","Cryptograf");
        auto* modeCb = new QComboBox;
        for (const auto& m : MODES) modeCb->addItem(m.name);
        modeCb->setCurrentIndex(s.value("defaultMode", 4).toInt());
        form->addRow("Режим по умолчанию:", modeCb);

        auto* modeNote = new QLabel("Применяется при следующем открытии вкладки «Шифровать»");
        modeNote->setStyleSheet("color:#7f8090; font-size:11px;");
        form->addRow("", modeNote);

        // Dark theme
        auto* darkChk = new QCheckBox("Тёмная тема");
        darkChk->setChecked(s.value("darkMode", false).toBool());
        form->addRow("Интерфейс:", darkChk);

        // Clear passwords
        auto* clearChk = new QCheckBox("Очищать пароли после операции");
        clearChk->setChecked(s.value("clearPasswords", false).toBool());
        form->addRow("Безопасность:", clearChk);

        // Save button
        auto* saveBtn = makeActionBtn("  Сохранить настройки", "#4f46e5", "#4338ca", "#a5b4fc");
        saveBtn->setMaximumWidth(220);
        auto* btnRow = new QWidget;
        auto* bh = new QHBoxLayout(btnRow);
        bh->setContentsMargins(0,14,0,0);
        bh->addWidget(saveBtn); bh->addStretch(1);
        vlay->addWidget(btnRow);
        vlay->addStretch(1);

        connect(saveBtn, &QPushButton::clicked, this, [=, this]() {
            QSettings qs("Cryptograf","Cryptograf");
            qs.setValue("defaultMode",     modeCb->currentIndex());
            qs.setValue("darkMode",        darkChk->isChecked());
            qs.setValue("clearPasswords",  clearChk->isChecked());

            // Apply default mode to encrypt combo immediately
            if (encModeCb_) encModeCb_->setCurrentIndex(modeCb->currentIndex());

            // Apply theme immediately
            applyTheme(darkChk->isChecked());

            logMsg("✓ Настройки сохранены.");
            QMessageBox::information(this,"Настройки","Настройки сохранены.");
        });

        return w;
    }

public:
    explicit CryptografWindow(QWidget* parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("Cryptograf — AES-256");
        resize(1060, 640);
        setMinimumSize(760, 500);
        {
            const bool dark = QSettings("Cryptograf","Cryptograf").value("darkMode", false).toBool();
            darkMode_ = dark;
            setStyleSheet(dark ? DARK_STYLE : APP_STYLE);
        }

        auto* central = new QWidget;
        central->setObjectName("central");
        setCentralWidget(central);
        auto* vlay = new QVBoxLayout(central);
        vlay->setContentsMargins(0, 0, 0, 0);
        vlay->setSpacing(0);

        auto* tabs = new QTabWidget;
        tabs->setDocumentMode(true);
        tabs->tabBar()->setExpanding(false);
        tabs->addTab(makeEncryptTab(),  "01  Шифровать");
        tabs->addTab(makeDecryptTab(),  "02  Расшифровать");
        tabs->addTab(makeSignTab(),     "03  Подпись");
        tabs->addTab(makeInfoTab(),     "04  Информация");
        tabs->addTab(makeBatchTab(),    "05  Пакет");
        tabs->addTab(makeNotesTab(),    "06  Заметки");
        tabs->addTab(makeSettingsTab(), "07  Настройки");
        vlay->addWidget(tabs, 1);

        // Dark log strip
        auto* logBar = new QWidget;
        logBar->setFixedHeight(72);
        logBar->setStyleSheet("background:#1a1b26;");
        auto* logLay = new QHBoxLayout(logBar);
        logLay->setContentsMargins(12, 4, 12, 4);
        log_ = new QPlainTextEdit;
        log_->setReadOnly(true);
        log_->setFont(monoFont(9));
        log_->setStyleSheet(
            "QPlainTextEdit { background:transparent;color:#a9b1d6;border:none; }"
            "QScrollBar:vertical { background:#1a1b26;width:5px;border-radius:3px; }"
            "QScrollBar::handle:vertical { background:#414868;border-radius:3px;min-height:16px; }"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical { height:0; }");
        log_->setFrameShape(QFrame::NoFrame);
        logLay->addWidget(log_);
        vlay->addWidget(logBar);

        statusBar()->setStyleSheet(
            "QStatusBar { background:#1a1b26;color:#565f89;font-size:11px;border:none; }");
        statusBar()->showMessage("Готово.");
        logMsg("Cryptograf запущен. Режимы: ECB, CBC, CFB, OFB, CTR, GCM, CCM, GCM-SIV, SIV.");
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
