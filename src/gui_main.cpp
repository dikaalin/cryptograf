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
#include <QTextBrowser>
#include <QProgressBar>
#include <QPushButton>
#include <QRandomGenerator>
#include <QScrollArea>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTabBar>
#include <QTabWidget>
#include <QTextFrame>
#include <QProcess>
#include <QTextFormat>
#include <QTextStream>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>
#include <cstring>
#include <functional>
#include <memory>

#include "aes_cipher.hpp"
#include "digital_sign.hpp"
#include "diagram_widgets.hpp"

// ── Translation helper (must be before any UI code) ───────────────────────────
namespace L {
    inline bool en() {
        static int v = -1;
        if (v < 0)
            v = QSettings("Cryptograf","Cryptograf")
                    .value("language","ru").toString() == "en" ? 1 : 0;
        return v == 1;
    }
    inline const char* s(const char* ru, const char* e) { return en() ? e : ru; }
    inline QString     q(const char* ru, const char* e) { return QString::fromUtf8(en() ? e : ru); }
} // namespace L

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

static QString lastDir() {
    return QSettings("Cryptograf","Cryptograf").value("lastDir", QDir::homePath()).toString();
}
static void saveDir(const QString& path) {
    if (path.isEmpty()) return;
    QSettings("Cryptograf","Cryptograf").setValue("lastDir", QFileInfo(path).absolutePath());
}

QWidget* makeFileRow(DropEdit*& edit, bool forOpen, QWidget* parent) {
    auto* row = new QWidget(parent);
    auto* h   = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0); h->setSpacing(6);
    edit = new DropEdit(row);
    edit->setPlaceholderText(forOpen ? L::q("Перетащите файл или нажмите «Обзор…»","Drag a file or click Browse…")
                                     : L::q("Путь к выходному файлу…","Output file path…"));
    auto* btn = new QPushButton(L::q("Обзор…","Browse…"), row);
    btn->setFixedWidth(76);
    QObject::connect(btn, &QPushButton::clicked, [edit, forOpen, parent]() {
        QString p = forOpen
            ? QFileDialog::getOpenFileName(parent, L::q("Открыть файл","Open file"), lastDir())
            : QFileDialog::getSaveFileName(parent, L::q("Сохранить как","Save as"), lastDir());
        if (!p.isEmpty()) { saveDir(p); edit->setText(p); }
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

QWidget* makeKeyFileRow(DropEdit*& edit, QWidget* parent) {
    auto* row = new QWidget(parent);
    auto* h   = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0); h->setSpacing(6);
    edit = new DropEdit(row);
    edit->setPlaceholderText(L::q("Необязательно — перетащите файл-ключ…","Optional — drag a key file…"));
    auto* btn = new QPushButton(L::q("Обзор…","Browse…"), row);
    btn->setFixedWidth(76);
    auto* clr = new QPushButton("✕", row);
    clr->setFixedWidth(26);
    clr->setObjectName("eyeBtn");
    QObject::connect(btn, &QPushButton::clicked, [edit, parent]() {
        QString p = QFileDialog::getOpenFileName(parent, L::q("Выбрать файл-ключ","Select key file"), lastDir());
        if (!p.isEmpty()) { saveDir(p); edit->setText(p); }
    });
    QObject::connect(clr, &QPushButton::clicked, [edit]() { edit->clear(); });
    h->addWidget(edit); h->addWidget(btn); h->addWidget(clr);
    return row;
}

QWidget* makeCopyRow(QLineEdit* display, std::function<QString()> fullTextFn, QWidget* parent) {
    auto* row = new QWidget(parent);
    auto* h   = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0); h->setSpacing(4);
    h->addWidget(display);
    auto* copy = new QPushButton(L::q("Копировать","Copy"), row);
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
    if (!p) return QString(
        "<html><body bgcolor='#1e2030'>"
        "<font color='#ff6b6b' face='monospace'>Не удалось разобрать файл .enc.</font>"
        "</body></html>");
    const QString plain = QString(
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
        .arg(p->is_folder ? "Архив папки (CDIR)" : L::q("Файл","File"))
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
    // bgcolor and <font color> map to QTextFrameFormat/QTextCharFormat inside Qt's
    // rich-text engine — they are NOT affected by system theme / QPalette.
    return QString(
        "<html><body bgcolor='#1e2030'>"
        "<font color='#ffffff' face='monospace'><pre>%1</pre></font>"
        "</body></html>")
        .arg(plain.toHtmlEscaped());
}


// Wrap a diagram widget in the dot-grid background pane (forward-declared; defined inside class)
static QWidget* wrapDiagram(QWidget* diagram, QWidget* parent, QList<DotGridWidget*>* reg = nullptr) {
    auto* bg   = new DotGridWidget(parent);
    if (reg) reg->append(bg);
    bg->setMinimumWidth(320);
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
QSplitter::handle { background: #d0d2e0; border-radius: 3px; margin: 4px 2px; }
QGroupBox {
    font-weight: 600;
    font-size: 12px;
    color: #2e2f38;
    border: 1.5px solid #dddee5;
    border-radius: 8px;
    margin-top: 2px;
    padding: 22px 4px 8px 4px;
}
QGroupBox::title {
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 8px;
    top: 4px;
    padding: 0 4px;
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
QSplitter::handle { background: #414868; border-radius: 3px; margin: 4px 2px; }
QGroupBox {
    font-weight: 600;
    font-size: 12px;
    color: #c0caf5;
    border: 1.5px solid #414868;
    border-radius: 8px;
    margin-top: 2px;
    padding: 22px 4px 8px 4px;
}
QGroupBox::title {
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 8px;
    top: 4px;
    padding: 0 4px;
}
)qss";

// ── CryptografWindow ──────────────────────────────────────────────────────────
class CryptografWindow : public QMainWindow {
    Q_OBJECT

    QPlainTextEdit*        log_         = nullptr;
    QPlainTextEdit*        historyView_ = nullptr;
    Worker*                work_        = nullptr;
    QComboBox*             encModeCb_   = nullptr;
    QTabWidget*            tabs_        = nullptr;
    bool                   darkMode_    = false;
    QList<DotGridWidget*>  diagrams_;

    void addToHistory(const QString& op, const QString& path, const QString& extra = {}) {
        QSettings s("Cryptograf", "Cryptograf");
        QStringList hist = s.value("history").toStringList();
        const auto ts = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
        QString entry = QStringLiteral("[%1] %2: %3").arg(ts, op, path);
        if (!extra.isEmpty()) entry += "  [" + extra + "]";
        hist.prepend(entry);
        const int maxH = s.value("maxHistory", 500).toInt();
        if (hist.size() > maxH) hist.resize(maxH);
        s.setValue("history", hist);
        if (historyView_) historyView_->setPlainText(hist.join('\n'));
    }

    void logMsg(const QString& msg) {
        const auto ts = QDateTime::currentDateTime().toString("hh:mm:ss");
        log_->appendPlainText(QStringLiteral("[%1] %2").arg(ts, msg));
    }

    void setBusy(bool busy) {
        for (auto* b : findChildren<QPushButton*>(QStringLiteral("opBtn")))
            b->setEnabled(!busy);
        statusBar()->showMessage(busy ? L::q("Выполняется операция…","Operation in progress…") : L::q("Готово.","Done."));
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
        splitter->setHandleWidth(6);
        splitter->setChildrenCollapsible(false);
        splitter->setStyleSheet(
            "QSplitter::handle { background: #d0d2e0; border-radius: 3px; margin: 4px 2px; }");

        auto* formPane = makeFormPane();
        auto* lay = new QVBoxLayout(formPane);
        lay->setContentsMargins(0, 0, 0, 0);
        lay->setSpacing(0);

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(24,20,24,0); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("01  Шифровать","01  Encrypt"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); lay->addWidget(row); }

        auto* scroll = new QScrollArea(formPane);
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        lay->addWidget(scroll, 1);

        auto* inner = new QWidget;
        auto* vlay  = new QVBoxLayout(inner);
        vlay->setContentsMargins(24, 10, 24, 20);
        vlay->setSpacing(10);
        scroll->setWidget(inner);

        auto* form = new QFormLayout;
        form->setSpacing(10); form->setContentsMargins(0, 0, 0, 0);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addLayout(form);

        auto* typeCombo = new QComboBox;
        typeCombo->addItem(L::q("Файл","File"));
        typeCombo->addItem(L::q("Папка","Folder"));
        form->addRow(L::q("Тип:","Type:"), typeCombo);

        const int defMode = QSettings("Cryptograf","Cryptograf").value("defaultMode", 4).toInt();
        auto* combo = new QComboBox;
        for (const auto& m : MODES) combo->addItem(m.name);
        combo->setCurrentIndex(defMode);
        encModeCb_ = combo;
        form->addRow(L::q("Режим:","Mode:"), combo);

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
        inEdit->setPlaceholderText(L::q("Перетащите файл или нажмите «Обзор…»","Drag a file or click Browse…"));
        auto* inBtn  = new QPushButton(L::q("Обзор…","Browse…"), inRow);
        inBtn->setFixedWidth(76);
        inH->addWidget(inEdit); inH->addWidget(inBtn);
        auto* inLabel = new QLabel(L::q("Входной файл:","Input file:"));
        form->addRow(inLabel, inRow);

        connect(inBtn, &QPushButton::clicked, [inEdit, typeCombo, inner]() {
            const bool isDir = typeCombo->currentIndex() == 1;
            QString p = isDir
                ? QFileDialog::getExistingDirectory(inner, L::q("Выбрать папку для шифрования","Select folder to encrypt"), lastDir())
                : QFileDialog::getOpenFileName(inner, L::q("Открыть файл","Open file"), lastDir());
            if (!p.isEmpty()) { saveDir(p); inEdit->setText(p); }
        });
        connect(typeCombo, &QComboBox::currentIndexChanged, [inEdit, inLabel](int i) {
            const bool isDir = i == 1;
            inLabel->setText(isDir ? L::q("Входная папка:","Input folder:") : L::q("Входной файл:","Input file:"));
            inEdit->setPlaceholderText(isDir ? L::q("Перетащите папку или нажмите «Обзор…»","Drag a folder or click Browse…")
                                             : L::q("Перетащите файл или нажмите «Обзор…»","Drag a file or click Browse…"));
        });

        DropEdit* outEdit;
        form->addRow(L::q("Выходной файл:","Output file:"), makeFileRow(outEdit, false, inner));
        connect(inEdit, &QLineEdit::textChanged, [outEdit](const QString& t) {
            if (outEdit->text().isEmpty() && !t.isEmpty()) outEdit->setText(t + ".enc");
        });

        QLineEdit *pw1, *pw2;
        form->addRow(L::q("Пароль:","Password:"), makePwRow(pw1, L::q("Введите пароль…","Enter password…"), inner));

        // ── Strength indicator ────────────────────────────────────────────────
        static const char* STRENGTH_COLORS[] =
            { "", "#ef4444", "#f97316", "#eab308", "#22c55e" };
        // Strength labels — computed at call time so they don't need capture.
        auto strengthLabel = [](int sc) -> const char* {
            static const char* RU[] = {"","Очень слабый","Слабый","Средний","Надёжный"};
            static const char* EN[] = {"","Very weak","Weak","Medium","Strong"};
            return (sc >= 0 && sc <= 4) ? (L::en() ? EN[sc] : RU[sc]) : "";
        };

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
        form->addRow(L::q("Надёжность:","Strength:"), strRow);

        connect(pw1, &QLineEdit::textChanged, [segs, strText, strengthLabel](const QString& pw) {
            const int sc = calcStrength(pw);
            for (int i = 0; i < 4; ++i)
                segs[i]->setStyleSheet(i < sc
                    ? QString("background:%1; border-radius:2px;").arg(STRENGTH_COLORS[sc])
                    : "background:#e0e1eb; border-radius:2px;");
            strText->setText(pw.isEmpty() ? "" : strengthLabel(sc));
            strText->setStyleSheet(sc > 0
                ? QString("color:%1; font-size:11px; font-weight:600; margin-left:2px;")
                      .arg(STRENGTH_COLORS[sc])
                : "color:#7f8090; font-size:11px; margin-left:2px;");
        });
        // ─────────────────────────────────────────────────────────────────────

        form->addRow(L::q("Подтверждение:","Confirm:"), makePwRow(pw2, L::q("Повторите пароль…","Repeat password…"), inner));

        DropEdit* keyfileEdit = nullptr;
        form->addRow(L::q("Файл-ключ:","Key file:"), makeKeyFileRow(keyfileEdit, inner));
        auto* kfNote = new QLabel(L::q("Необязательно. Если указан — требуется при расшифровании.","Optional. If set — required for decryption."));
        kfNote->setWordWrap(true);
        kfNote->setStyleSheet("color:#7f8090;font-size:11px;padding:2px 0;");
        form->addRow("", kfNote);

        auto* secDelChk = new QCheckBox(L::q("Безопасно удалить исходный файл после шифрования","Securely delete source file after encryption"));
        secDelChk->setStyleSheet("QCheckBox { color: #ffffff; } QCheckBox:disabled { color: #888; }");
        form->addRow("", secDelChk);
        connect(typeCombo, &QComboBox::currentIndexChanged, [secDelChk](int i) {
            secDelChk->setEnabled(i == 0);
        });

        auto* btn = makeActionBtn(L::q("  Зашифровать","  Encrypt"), "#4f46e5", "#4338ca", "#a5b4fc");
        form->addRow("", btn);

        auto* progBar = new QProgressBar;
        progBar->setRange(0, 100);
        progBar->setValue(0);
        progBar->setVisible(false);
        progBar->setTextVisible(false);
        form->addRow("", progBar);

        auto* resultBox = new QGroupBox(L::q("Результат шифрования","Encryption Result"));
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
        rform->addRow(L::q("Шифртекст:","Ciphertext:"), makeCopyRow(ctDisplay, getCTHex, resultBox));

        auto* tagLabel   = new QLabel(L::q("Имитовставка:","Auth tag:"));
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
            if (in.isEmpty())  { QMessageBox::warning(this,L::q("Ошибка","Error"),
                                     isDir ? "Укажите входную папку." : "Укажите входной файл."); return; }
            if (out.isEmpty()) { QMessageBox::warning(this,L::q("Ошибка","Error"),"Укажите выходной файл."); return; }
            if (p1.isEmpty())  { QMessageBox::warning(this,L::q("Ошибка","Error"),"Пароль не должен быть пустым."); return; }
            if (p1 != p2)      { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Пароли не совпадают.","Passwords do not match.")); return; }
            if (isDir) {
                if (!QDir(in).exists()) { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Папка не найдена.","Folder not found.")); return; }
            } else {
                if (!QFile::exists(in)) { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Входной файл не найден.","Input file not found.")); return; }
            }
            if (QFile::exists(out)) {
                if (QMessageBox::question(this,L::q("Файл существует","File exists"),
                        QString("'%1' уже существует.\nПерезаписать?").arg(out))
                        != QMessageBox::Yes) return;
                QFile::remove(out);
            }
            resultBox->setVisible(false);
            progBar->setValue(0);
            progBar->setVisible(true);
            setBusy(true);
            logMsg(L::q("Шифрование [%1]: %2  →  %3","Encrypting [%1]: %2  →  %3").arg(combo->currentText(), in, out));
            work_ = new Worker;
            const auto mode    = MODES[mi].mode;
            const auto kfPath  = keyfileEdit->text().trimmed();
            const bool doSecDel = secDelChk->isChecked() && !isDir;
            const size_t iters = static_cast<size_t>(
                QSettings("Cryptograf","Cryptograf").value("kdfIterations", 100000).toInt());
            if (isDir) {
                work_->task = [i=in.toStdString(),o=out.toStdString(),
                                p=p1.toStdString(),kf=kfPath.toStdString(),mode,iters,w=work_]() {
                    crypto::encrypt_dir(i, o, p, mode, kf, iters, [w](int64_t d, int64_t t) {
                        w->reportProgress(d, t);
                    });
                };
            } else {
                work_->task = [i=in.toStdString(),o=out.toStdString(),
                                p=p1.toStdString(),kf=kfPath.toStdString(),mode,iters,doSecDel,w=work_]() {
                    crypto::encrypt_file(i, o, p, mode, kf, iters, [w](int64_t d, int64_t t) {
                        w->reportProgress(d, t);
                    });
                    if (doSecDel) crypto::secure_delete(i);
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
                        tagLabel->setText(parts->is_aead ? L::q("Имитовставка:","Auth tag:") : "HMAC-SHA256:");
                        tagDisplay->setText(QString::fromLatin1(parts->tag.toHex()));
                        resultBox->setVisible(true);
                    }
                    logMsg(QString("✓ Готово. Шифртекст: %1 байт, тег: %2 байт")
                           .arg(parts?parts->ciphertext.size():0).arg(parts?parts->tag.size():0));
                    addToHistory(isDir ? L::q("Шифрование папки","Folder encryption") : L::q("Шифрование","Encryption"), out, combo->currentText());
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
            if (i >= 0 && i < MODE_COUNT)
                diagram->setMode(MODES[i].mode);
        });
        diagram->setMode(MODES[4].mode); // CTR default

        splitter->addWidget(formPane);
        splitter->addWidget(wrapDiagram(diagram, splitter, &diagrams_));
        splitter->setStretchFactor(0, 0);
        splitter->setStretchFactor(1, 1);
        splitter->setSizes({380, 700});
        return splitter;
    }

    QWidget* makeDecryptTab() {
        auto* splitter = new QSplitter(Qt::Horizontal);
        splitter->setHandleWidth(6);
        splitter->setChildrenCollapsible(false);
        splitter->setStyleSheet(
            "QSplitter::handle { background: #d0d2e0; border-radius: 3px; margin: 4px 2px; }");

        auto* formPane = makeFormPane();
        auto* vlay     = new QVBoxLayout(formPane);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(0,0,0,0); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("02  Расшифровать","02  Decrypt"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); vlay->addWidget(row); }

        auto* form = new QFormLayout;
        form->setSpacing(10); form->setContentsMargins(0, 4, 0, 0);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addLayout(form);

        DropEdit* inEdit;
        form->addRow(L::q("Зашифрованный файл:","Encrypted file:"), makeFileRow(inEdit, true, formPane));

        // Output row (manual — label and picker switch on folder-archive detection)
        auto* outRow = new QWidget(formPane);
        auto* outH   = new QHBoxLayout(outRow);
        outH->setContentsMargins(0,0,0,0); outH->setSpacing(6);
        auto* outEdit = new DropEdit(outRow);
        outEdit->setPlaceholderText(L::q("Путь к выходному файлу…","Output file path…"));
        auto* outBtn  = new QPushButton(L::q("Обзор…","Browse…"), outRow);
        outBtn->setFixedWidth(76);
        outH->addWidget(outEdit); outH->addWidget(outBtn);
        auto* outLabel = new QLabel(L::q("Выходной файл:","Output file:"));
        form->addRow(outLabel, outRow);

        connect(outBtn, &QPushButton::clicked, [outEdit, inEdit, formPane]() {
            const bool isFolder = crypto::is_dir_archive(inEdit->text().trimmed().toStdString());
            QString p = isFolder
                ? QFileDialog::getExistingDirectory(formPane, L::q("Выбрать папку назначения","Select output folder"), lastDir())
                : QFileDialog::getSaveFileName(formPane, L::q("Сохранить как","Save as"), lastDir());
            if (!p.isEmpty()) { saveDir(p); outEdit->setText(p); }
        });

        connect(inEdit, &QLineEdit::textChanged, [outEdit, outLabel](const QString& t) {
            if (t.isEmpty()) return;
            const bool isFolder = crypto::is_dir_archive(t.trimmed().toStdString());
            outLabel->setText(isFolder ? "Папка назначения:" : L::q("Выходной файл:","Output file:"));
            outEdit->setPlaceholderText(isFolder ? "Путь к папке…" : L::q("Путь к выходному файлу…","Output file path…"));
            if (outEdit->text().isEmpty()) {
                QString o = t.trimmed();
                if (o.endsWith(".enc", Qt::CaseInsensitive)) o.chop(4); else o += ".dec";
                outEdit->setText(o);
            }
        });

        QLineEdit* pw;
        form->addRow(L::q("Пароль:","Password:"), makePwRow(pw, L::q("Введите пароль…","Enter password…"), formPane));

        DropEdit* dkeyfileEdit = nullptr;
        form->addRow(L::q("Файл-ключ:","Key file:"), makeKeyFileRow(dkeyfileEdit, formPane));
        auto* dkfNote = new QLabel("Если использовался при шифровании — обязателен.");
        dkfNote->setStyleSheet("color:#7f8090;font-size:11px;padding:2px 0;");
        form->addRow("", dkfNote);

        auto* btn = makeActionBtn(L::q("  Расшифровать","  Decrypt"), "#16a34a", "#15803d", "#86efac");
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
            if (in.isEmpty())       { QMessageBox::warning(this,L::q("Ошибка","Error"),"Укажите файл для расшифрования."); return; }
            if (out.isEmpty())      { QMessageBox::warning(this,L::q("Ошибка","Error"),"Укажите выходной путь."); return; }
            if (p.isEmpty())        { QMessageBox::warning(this,L::q("Ошибка","Error"),"Пароль не должен быть пустым."); return; }
            if (!QFile::exists(in)) { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Входной файл не найден.","Input file not found.")); return; }

            const bool isFolder = crypto::is_dir_archive(in.toStdString());
            if (!isFolder) {
                if (QFile::exists(out)) {
                    if (QMessageBox::question(this,L::q("Файл существует","File exists"),
                            QString("'%1' уже существует.\nПерезаписать?").arg(out))
                            != QMessageBox::Yes) return;
                    QFile::remove(out);
                }
            }

            progBar->setValue(0);
            progBar->setVisible(true);
            setBusy(true);
            logMsg(L::q("Расшифрование: %1  →  %2","Decrypting: %1  →  %2").arg(in, out));
            work_ = new Worker;
            const auto dkfPath = dkeyfileEdit->text().trimmed();
            if (isFolder) {
                work_->task = [i=in.toStdString(),o=out.toStdString(),
                                pw=p.toStdString(),kf=dkfPath.toStdString(),w=work_]() {
                    crypto::decrypt_dir(i, o, pw, kf, [w](int64_t d, int64_t t) {
                        w->reportProgress(d, t);
                    });
                };
            } else {
                work_->task = [i=in.toStdString(),o=out.toStdString(),
                                pw=p.toStdString(),kf=dkfPath.toStdString(),w=work_]() {
                    crypto::decrypt_file(i, o, pw, kf, [w](int64_t d, int64_t t) {
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
                    addToHistory(isFolder ? L::q("Расшифрование папки","Folder decryption") : L::q("Расшифрование","Decryption"), out);
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
        splitter->setSizes({380, 700});
        return splitter;
    }

    QWidget* makeSignTab() {
        auto* splitter = new QSplitter(Qt::Horizontal);
        splitter->setHandleWidth(6);
        splitter->setChildrenCollapsible(false);
        splitter->setStyleSheet(
            "QSplitter::handle { background: #d0d2e0; border-radius: 3px; margin: 4px 2px; }");

        auto* formPane = makeFormPane();
        auto* fpLay = new QVBoxLayout(formPane);
        fpLay->setContentsMargins(0, 0, 0, 0);
        fpLay->setSpacing(0);

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(24,16,24,8); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("03  Подпись","03  Sign"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); fpLay->addWidget(row); }

        auto* scroll = new QScrollArea(formPane);
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        fpLay->addWidget(scroll, 1);

        auto* inner = new QWidget;
        auto* vlay  = new QVBoxLayout(inner);
        vlay->setContentsMargins(24, 4, 24, 20);
        vlay->setSpacing(10);
        scroll->setWidget(inner);

        // Key gen
        auto* keyBox  = new QGroupBox(L::q("Генерация ключевой пары (ECDSA P-256)","Generate Key Pair (ECDSA P-256)"));
        auto* keyForm = new QFormLayout(keyBox);
        keyForm->setSpacing(8); keyForm->setContentsMargins(12, 8, 12, 8);
        keyForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        keyForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        DropEdit *privEdit, *pubEdit;
        keyForm->addRow(L::q("Закрытый ключ:","Private key:"), makeFileRow(privEdit, false, inner));
        keyForm->addRow(L::q("Открытый ключ:","Public key:"), makeFileRow(pubEdit,  false, inner));
        auto* keyBtn = makeActionBtn(L::q("  Сгенерировать ключи","  Generate Keys"), "#7c3aed", "#6d28d9", "#c4b5fd");
        keyForm->addRow("", keyBtn);
        vlay->addWidget(keyBox);

        connect(keyBtn, &QPushButton::clicked, this, [=, this]() {
            const QString priv = privEdit->text().trimmed();
            const QString pub  = pubEdit->text().trimmed();
            if (priv.isEmpty()) { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Укажите путь для закрытого ключа.","Specify path for the private key.")); return; }
            if (pub.isEmpty())  { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Укажите путь для открытого ключа.","Specify path for the public key.")); return; }
            setBusy(true); logMsg(L::q("Генерация ключей ECDSA P-256…","Generating ECDSA P-256 keys…"));
            work_ = new Worker;
            work_->task = [p=priv.toStdString(),q=pub.toStdString()]() { crypto::generate_ec_keypair(p,q); };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) logMsg(L::q("✓ Ключи сохранены: ","✓ Keys saved: ") + priv + " / " + pub);
                else  { logMsg("✗ "+err); QMessageBox::critical(this,L::q("Ошибка","Error"),err); }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        // Sign
        auto* signBox  = new QGroupBox(L::q("Подписать файл","Sign File"));
        auto* signForm = new QFormLayout(signBox);
        signForm->setSpacing(8); signForm->setContentsMargins(12, 8, 12, 8);
        signForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        signForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        DropEdit *sInEdit, *sKeyEdit, *sSigEdit;
        signForm->addRow(L::q("Файл:","File:"),          makeFileRow(sInEdit,  true,  inner));
        signForm->addRow(L::q("Закрытый ключ:","Private key:"), makeFileRow(sKeyEdit, true,  inner));
        signForm->addRow(L::q("Файл подписи:","Signature file:"),  makeFileRow(sSigEdit, false, inner));
        connect(sInEdit, &QLineEdit::textChanged, [sSigEdit](const QString& t) {
            if (sSigEdit->text().isEmpty() && !t.isEmpty()) sSigEdit->setText(t + ".sig");
        });
        auto* signBtn = makeActionBtn(L::q("  Подписать","  Sign"), "#0369a1", "#075985", "#7dd3fc");
        signForm->addRow("", signBtn);
        vlay->addWidget(signBox);

        connect(signBtn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = sInEdit->text().trimmed();
            const QString key = sKeyEdit->text().trimmed();
            const QString sig = sSigEdit->text().trimmed();
            if (in.isEmpty())        { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Укажите подписываемый файл.","Specify the file to sign.")); return; }
            if (key.isEmpty())       { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Укажите файл закрытого ключа.","Specify the private key file.")); return; }
            if (sig.isEmpty())       { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Укажите путь для подписи.","Specify the signature output path.")); return; }
            if (!QFile::exists(in))  { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Файл не найден.","File not found.")); return; }
            if (!QFile::exists(key)) { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Ключ не найден.","Key not found.")); return; }
            setBusy(true); logMsg(L::q("Подпись файла: ","Signing file: ") + in);
            work_ = new Worker;
            work_->task = [i=in.toStdString(),k=key.toStdString(),s=sig.toStdString()]() { crypto::sign_file(i,k,s); };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) logMsg(L::q("✓ Подпись записана: ","✓ Signature saved: ") + sig);
                else  { logMsg("✗ "+err); QMessageBox::critical(this,"Ошибка подписи",err); }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        // Verify
        auto* verBox  = new QGroupBox(L::q("Проверить подпись","Verify Signature"));
        auto* verForm = new QFormLayout(verBox);
        verForm->setSpacing(8); verForm->setContentsMargins(12, 8, 12, 8);
        verForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        verForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        DropEdit *vInEdit, *vSigEdit, *vKeyEdit;
        verForm->addRow(L::q("Файл:","File:"),           makeFileRow(vInEdit,  true, inner));
        verForm->addRow(L::q("Файл подписи:","Signature file:"),  makeFileRow(vSigEdit, true, inner));
        verForm->addRow(L::q("Открытый ключ:","Public key:"), makeFileRow(vKeyEdit, true, inner));
        auto* verBtn = makeActionBtn(L::q("  Проверить подпись","  Verify Signature"), "#16a34a", "#15803d", "#86efac");
        verForm->addRow("", verBtn);
        vlay->addWidget(verBox);
        vlay->addStretch(1);

        connect(verBtn, &QPushButton::clicked, this, [=, this]() {
            const QString in  = vInEdit->text().trimmed();
            const QString sig = vSigEdit->text().trimmed();
            const QString key = vKeyEdit->text().trimmed();
            if (in.isEmpty())        { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Укажите проверяемый файл.","Specify the file to verify.")); return; }
            if (sig.isEmpty())       { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Укажите файл подписи.","Specify the signature file.")); return; }
            if (key.isEmpty())       { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Укажите файл открытого ключа.","Specify the public key file.")); return; }
            if (!QFile::exists(in))  { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Файл не найден.","File not found.")); return; }
            if (!QFile::exists(sig)) { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Файл подписи не найден.","Signature file not found.")); return; }
            if (!QFile::exists(key)) { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Ключ не найден.","Key not found.")); return; }
            setBusy(true); logMsg(L::q("Проверка подписи: ","Verifying signature: ") + in);
            work_ = new Worker;
            auto result = std::make_shared<bool>(false);
            work_->task = [i=in.toStdString(),s=sig.toStdString(),k=key.toStdString(),result]() {
                *result = crypto::verify_file(i,s,k);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                if (ok) {
                    if (*result) {
                        logMsg(L::q("✓ Подпись ВЕРНА. Файл не изменён.","✓ Signature VALID. File not modified."));
                        QMessageBox::information(this,L::q("Результат проверки","Verification Result"),
                            L::q("Подпись верна.\nФайл не был изменён после подписания.","Signature is valid.\nFile has not been modified since signing."));
                    } else {
                        logMsg(L::q("✗ Подпись НЕДЕЙСТВИТЕЛЬНА.","✗ Signature INVALID."));
                        QMessageBox::critical(this,L::q("Результат проверки","Verification Result"),
                            L::q("Подпись недействительна!\nФайл мог быть изменён или используется другой ключ.","Signature invalid!\nFile may have been modified or a different key was used."));
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
        splitter->setSizes({380, 700});
        return splitter;
    }

    QWidget* makeInfoTab() {
        auto* splitter = new QSplitter(Qt::Horizontal);
        splitter->setHandleWidth(6);
        splitter->setChildrenCollapsible(false);
        splitter->setStyleSheet(
            "QSplitter::handle { background: #d0d2e0; border-radius: 3px; margin: 4px 2px; }");

        auto* formPane = makeFormPane();
        auto* vlay     = new QVBoxLayout(formPane);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(0,0,0,0); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("04  Информация","04  File Info"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); vlay->addWidget(row); }
        auto* subLbl = new QLabel(L::q("Разбор заголовка и метаданных .enc файла","Parse .enc file header and metadata"));
        subLbl->setStyleSheet("font-size:12px;color:#7f8090;");
        vlay->addWidget(subLbl);

        auto* row = new QWidget;
        auto* h   = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, 0); h->setSpacing(8);
        auto* lbl = new QLabel(L::q("Файл:","File:"));
        lbl->setFixedWidth(44);
        auto* fileEdit  = new DropEdit;
        fileEdit->setPlaceholderText("Перетащите или выберите .enc файл…");
        auto* browseBtn = new QPushButton(L::q("Обзор…","Browse…"));
        browseBtn->setFixedWidth(76);
        h->addWidget(lbl); h->addWidget(fileEdit); h->addWidget(browseBtn);
        vlay->addWidget(row);

        connect(browseBtn, &QPushButton::clicked, [fileEdit, this]() {
            auto p = QFileDialog::getOpenFileName(this, L::q("Открыть зашифрованный файл","Open encrypted file"),
                         {}, "Зашифрованные файлы (*.enc);;Все файлы (*)");
            if (!p.isEmpty()) fileEdit->setText(p);
        });

        auto* view = new QTextBrowser;
        view->setObjectName("infoView");
        view->setReadOnly(true);
        view->setOpenLinks(false);
        view->setPlaceholderText(L::q("Информация о файле появится здесь…","File information will appear here…"));

        // Force document background via QTextFrameFormat — painted by Qt's text
        // layout engine, completely independent of QPalette / system theme.
        auto applyDocBg = [](QTextBrowser* v) {
            QTextFrameFormat ff;
            ff.setBackground(QColor("#1e2030"));
            v->document()->rootFrame()->setFrameFormat(ff);
        };
        applyDocBg(view);

        // Best-effort palette for the viewport area outside the document.
        QPalette vp;
        vp.setColor(QPalette::Base,       QColor("#1e2030"));
        vp.setColor(QPalette::Text,       QColor("#ffffff"));
        vp.setColor(QPalette::Window,     QColor("#1e2030"));
        vp.setColor(QPalette::WindowText, QColor("#ffffff"));
        view->setPalette(vp);
        view->viewport()->setPalette(vp);

        vlay->addWidget(view, 1);

        connect(fileEdit, &QLineEdit::textChanged, [view, applyDocBg](const QString& t) {
            if (t.isEmpty()) { view->clear(); applyDocBg(view); return; }
            // setHtml() replaces the document, resetting rootFrame format — re-apply.
            view->setHtml(buildFileInfo(t));
            applyDocBg(view);
        });

        splitter->addWidget(formPane);
        splitter->addWidget(wrapDiagram(new StaticSvgDiagram(":/diagrams/info.svg"), splitter, &diagrams_));
        splitter->setStretchFactor(0, 0);
        splitter->setStretchFactor(1, 1);
        splitter->setSizes({380, 700});
        return splitter;
    }

    // ── 05  Пакетное шифрование ───────────────────────────────────────────────
    QWidget* makeBatchTab() {
        auto* w    = new QWidget;
        auto* vlay = new QVBoxLayout(w);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(0,0,0,0); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("05  Пакетное шифрование","05  Batch Encrypt"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); vlay->addWidget(row); }
        auto* subLbl = new QLabel(L::q("Зашифруйте или расшифруйте несколько файлов за один раз","Encrypt or decrypt multiple files at once"));
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
        auto* clrBtn = new QPushButton(L::q("Очистить список","Clear list"));
        listH->addWidget(addBtn); listH->addWidget(delBtn); listH->addWidget(clrBtn);
        listH->addStretch(1);
        vlay->addWidget(listBtnRow);

        connect(addBtn, &QPushButton::clicked, [fileList, w]() {
            const auto files = QFileDialog::getOpenFileNames(w, L::q("Выбрать файлы","Select files"), lastDir());
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
        form->addRow(L::q("Пароль:","Password:"), makePwRow(pw, "Пароль для всех файлов…", w));

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
                QMessageBox::warning(this,L::q("Ошибка","Error"),"Список файлов пуст."); return;
            }
            if (pw->text().isEmpty()) {
                QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Введите пароль.","Enter a password.")); return;
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
                            const size_t iters = static_cast<size_t>(
                                QSettings("Cryptograf","Cryptograf").value("kdfIterations",100000).toInt());
                            crypto::encrypt_file(in, out, password.toStdString(), mode, {}, iters);
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

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(0,0,0,0); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("06  Заметки","06  Notes"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); vlay->addWidget(row); }
        auto* subLbl = new QLabel(L::q("Текст шифруется напрямую — без временных файлов на диске","Text is encrypted directly — no temp files on disk"));
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
        form->addRow(L::q("Режим:","Mode:"), modeCombo);

        QLineEdit* pw;
        form->addRow(L::q("Пароль:","Password:"), makePwRow(pw, "Пароль заметки…", w));

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
            if (text.trimmed().isEmpty()) { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Заметка пуста.","Note is empty.")); return; }
            if (p.isEmpty())              { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Введите пароль.","Enter a password.")); return; }
            QString outPath = QFileDialog::getSaveFileName(this, L::q("Сохранить заметку","Save note"), lastDir(),
                                L::q("Зашифрованные заметки (*.enc);;Все файлы (*)","Encrypted notes (*.enc);;All files (*)"));
            if (outPath.isEmpty()) return;
            if (!outPath.endsWith(".enc", Qt::CaseInsensitive)) outPath += ".enc";
            if (QFile::exists(outPath)) QFile::remove(outPath);

            const auto mode = MODES[modeCombo->currentIndex()].mode;
            setBusy(true); statusLbl->setText(L::q("Шифрование…","Encrypting…"));
            work_ = new Worker;
            saveDir(outPath);
            const size_t iters = static_cast<size_t>(
                QSettings("Cryptograf","Cryptograf").value("kdfIterations",100000).toInt());
            work_->task = [text, o=outPath.toStdString(), p=p.toStdString(), mode, iters]() {
                const QString tmp = QDir::tempPath() + "/cg_note.tmp";
                {
                    QFile f(tmp);
                    if (!f.open(QIODevice::WriteOnly))
                        throw std::runtime_error("Не удалось создать временный файл");
                    QTextStream(&f) << text;
                }
                try {
                    crypto::encrypt_file(tmp.toStdString(), o, p, mode, {}, iters);
                } catch (...) { QFile::remove(tmp); throw; }
                QFile::remove(tmp);
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                setBusy(false);
                statusLbl->setText(ok ? "✓ Заметка сохранена: " + outPath : "✗ " + err);
                if (!ok) { QFile::remove(outPath); QMessageBox::critical(this,L::q("Ошибка","Error"),err); }
                else logMsg("✓ Заметка зашифрована: " + outPath);
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        // Load: decrypt .enc → show in editor
        connect(loadBtn, &QPushButton::clicked, this, [=, this]() {
            const QString p = pw->text();
            if (p.isEmpty()) { QMessageBox::warning(this,L::q("Ошибка","Error"),L::q("Введите пароль.","Enter a password.")); return; }
            QString inPath = QFileDialog::getOpenFileName(this, L::q("Открыть заметку","Open note"), lastDir(),
                               L::q("Зашифрованные заметки (*.enc);;Все файлы (*)","Encrypted notes (*.enc);;All files (*)"));
            if (inPath.isEmpty()) return;

            setBusy(true); statusLbl->setText(L::q("Расшифрование…","Decrypting…"));
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

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(0,0,0,4); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("07  Настройки","07  Settings"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); vlay->addWidget(row); }

        auto* box  = new QGroupBox(L::q("Параметры приложения","Application Settings"));
        auto* form = new QFormLayout(box);
        form->setSpacing(14); form->setContentsMargins(20,16,20,16);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addWidget(box);

        QSettings s("Cryptograf","Cryptograf");
        auto* modeCb = new QComboBox;
        for (const auto& m : MODES) modeCb->addItem(m.name);
        modeCb->setCurrentIndex(s.value("defaultMode", 4).toInt());
        form->addRow(L::q("Режим по умолчанию:","Default mode:"), modeCb);

        auto* modeNote = new QLabel(L::q("Применяется при следующем открытии вкладки «Шифровать»","Applied next time the Encrypt tab is opened"));
        modeNote->setStyleSheet("color:#7f8090; font-size:11px;");
        modeNote->setWordWrap(true);
        form->addRow(modeNote);

        // PBKDF2 iterations
        auto* iterCb = new QComboBox;
        const QList<QPair<QString,int>> iterOptions = {
            {"100 000  (по умолчанию, быстро)", 100000},
            {"250 000  (умеренно)",             250000},
            {"500 000  (надёжно, медленнее)",   500000},
            {"1 000 000  (максимум)",           1000000},
        };
        const int savedIter = s.value("kdfIterations", 100000).toInt();
        for (const auto& [label, val] : iterOptions) {
            iterCb->addItem(label, val);
            if (val == savedIter) iterCb->setCurrentIndex(iterCb->count() - 1);
        }
        form->addRow(L::q("Итерации PBKDF2:","PBKDF2 iterations:"), iterCb);
        auto* iterNote = new QLabel(L::q("Больше итераций → сложнее перебор пароля, но медленнее шифрование","More iterations → harder brute force, but slower encryption"));
        iterNote->setStyleSheet("color:#7f8090; font-size:11px;");
        iterNote->setWordWrap(true);
        form->addRow(iterNote);

        // Max history
        auto* maxHistSpin = new QSpinBox;
        maxHistSpin->setRange(50, 5000);
        maxHistSpin->setSingleStep(50);
        maxHistSpin->setValue(s.value("maxHistory", 500).toInt());
        maxHistSpin->setSuffix(L::q(" записей"," records"));
        form->addRow(L::q("Макс. история:","Max history:"), maxHistSpin);

        // Language
        auto* langCb = new QComboBox;
        langCb->addItem(L::q("Русский","Russian"), "ru");
        langCb->addItem("English", "en");
        const QString savedLang = s.value("language","ru").toString();
        langCb->setCurrentIndex(savedLang == "en" ? 1 : 0);
        form->addRow(L::q("Язык / Language:","Language / Язык:"), langCb);
        auto* langNote = new QLabel(L::q("При смене языка приложение перезапустится автоматически.","The app will restart automatically when the language is changed."));
        langNote->setStyleSheet("color:#7f8090; font-size:11px;");
        langNote->setWordWrap(true);
        form->addRow(langNote);

        // Dark theme
        auto* darkChk = new QCheckBox(L::q("Тёмная тема","Dark theme"));
        darkChk->setChecked(s.value("darkMode", false).toBool());
        form->addRow(L::q("Интерфейс:","Interface:"), darkChk);

        // Clear passwords
        auto* clearChk = new QCheckBox(L::q("Очищать пароли после операции","Clear passwords after operation"));
        clearChk->setChecked(s.value("clearPasswords", false).toBool());
        form->addRow(L::q("Безопасность:","Security:"), clearChk);

        // Save button
        auto* saveBtn = makeActionBtn(L::q("  Сохранить настройки","  Save Settings"), "#4f46e5", "#4338ca", "#a5b4fc");
        saveBtn->setMaximumWidth(220);
        auto* btnRow = new QWidget;
        auto* bh = new QHBoxLayout(btnRow);
        bh->setContentsMargins(0,14,0,0);
        bh->addWidget(saveBtn); bh->addStretch(1);
        vlay->addWidget(btnRow);
        vlay->addStretch(1);

        connect(saveBtn, &QPushButton::clicked, this, [=, this]() {
            QSettings qs("Cryptograf","Cryptograf");
            const QString prevLang = qs.value("language","ru").toString();
            const QString newLang  = langCb->currentData().toString();

            qs.setValue("defaultMode",    modeCb->currentIndex());
            qs.setValue("kdfIterations",  iterCb->currentData().toInt());
            qs.setValue("maxHistory",     maxHistSpin->value());
            qs.setValue("language",       newLang);
            qs.setValue("darkMode",       darkChk->isChecked());
            qs.setValue("clearPasswords", clearChk->isChecked());
            qs.sync();

            if (newLang != prevLang) {
                // Language changed — restart to rebuild all UI strings.
                QProcess::startDetached(QApplication::applicationFilePath(), {});
                QApplication::quit();
                return;
            }

            // Apply other changes immediately (no restart needed).
            if (encModeCb_) encModeCb_->setCurrentIndex(modeCb->currentIndex());
            applyTheme(darkChk->isChecked());

            logMsg(L::q("✓ Настройки сохранены.","✓ Settings saved."));
            QMessageBox::information(this,
                L::q("Настройки","Settings"),
                L::q("Настройки сохранены.","Settings saved."));
        });

        return w;
    }

    // ── 08  Целостность файлов ────────────────────────────────────────────────
    QWidget* makeHashTab() {
        auto* w    = new QWidget;
        auto* vlay = new QVBoxLayout(w);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(0,0,0,0); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("08  Целостность","08  Integrity"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); vlay->addWidget(row); }
        auto* subLbl = new QLabel(L::q("Вычисление и проверка контрольных сумм файлов (SHA-256, BLAKE2b-512)","Calculate and verify file checksums (SHA-256, BLAKE2b-512)"));
        subLbl->setStyleSheet("font-size:12px;color:#7f8090;");
        vlay->addWidget(subLbl);

        auto* form = new QFormLayout;
        form->setSpacing(10); form->setContentsMargins(0, 8, 0, 0);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addLayout(form);

        DropEdit* fileEdit;
        form->addRow(L::q("Файл:","File:"), makeFileRow(fileEdit, true, w));

        auto* sha256Display = new QLineEdit;
        sha256Display->setReadOnly(true); sha256Display->setFont(monoFont(9));
        sha256Display->setPlaceholderText("—");
        auto* sha256Row = makeCopyRow(sha256Display, [sha256Display]{ return sha256Display->text(); }, w);
        form->addRow("SHA-256:", sha256Row);

        auto* blake2Display = new QLineEdit;
        blake2Display->setReadOnly(true); blake2Display->setFont(monoFont(9));
        blake2Display->setPlaceholderText("—");
        auto* blake2Row = makeCopyRow(blake2Display, [blake2Display]{ return blake2Display->text(); }, w);
        form->addRow("BLAKE2b-512:", blake2Row);

        auto* calcBtn = makeActionBtn(L::q("  Вычислить хэши","  Compute Hashes"), "#4f46e5", "#4338ca", "#a5b4fc");
        form->addRow("", calcBtn);

        auto* hashProgBar = new QProgressBar;
        hashProgBar->setRange(0, 0);
        hashProgBar->setVisible(false); hashProgBar->setTextVisible(false);
        form->addRow("", hashProgBar);

        // ── Verify section ────────────────────────────────────────────────────
        auto* verBox  = new QGroupBox(L::q("Проверить контрольную сумму","Verify Checksum"));
        auto* verForm = new QFormLayout(verBox);
        verForm->setSpacing(8); verForm->setContentsMargins(12, 8, 12, 8);
        verForm->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        verForm->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

        auto* expectedEdit = new QLineEdit;
        expectedEdit->setPlaceholderText("Вставьте ожидаемую контрольную сумму (SHA-256 или BLAKE2b-512)…");
        expectedEdit->setFont(monoFont(10));
        verForm->addRow(L::q("Ожидаемый хэш:","Expected hash:"), expectedEdit);

        auto* verResult = new QLabel;
        verResult->setWordWrap(true);
        verForm->addRow("", verResult);

        auto* verBtn = makeActionBtn(L::q("  Проверить","  Verify"), "#0369a1", "#075985", "#7dd3fc");
        verForm->addRow("", verBtn);
        vlay->addWidget(verBox);
        vlay->addStretch(1);

        // Compute on button click
        connect(calcBtn, &QPushButton::clicked, this, [=, this]() {
            const QString path = fileEdit->text().trimmed();
            if (path.isEmpty()) {
                QMessageBox::warning(this, L::q("Ошибка","Error"), "Укажите файл."); return;
            }
            if (!QFile::exists(path)) {
                QMessageBox::warning(this, L::q("Ошибка","Error"), L::q("Файл не найден.","File not found.")); return;
            }
            if (work_) { QMessageBox::warning(this,"Занято","Дождитесь завершения текущей операции."); return; }
            sha256Display->clear(); blake2Display->clear();
            hashProgBar->setVisible(true);
            setBusy(true);
            logMsg(L::q("Вычисление хэшей: ","Computing hashes: ") + path);

            auto sha256Result = std::make_shared<QString>();
            auto blake2Result = std::make_shared<QString>();
            work_ = new Worker;
            work_->task = [p=path.toStdString(), sha256Result, blake2Result]() {
                *sha256Result = QString::fromStdString(crypto::sha256_file(p));
                *blake2Result = QString::fromStdString(crypto::blake2b_file(p));
            };
            connect(work_, &Worker::done, this, [=, this](bool ok, QString err) {
                hashProgBar->setVisible(false);
                setBusy(false);
                if (ok) {
                    sha256Display->setText(*sha256Result);
                    blake2Display->setText(*blake2Result);
                    logMsg(L::q("✓ Хэши вычислены.","✓ Hashes computed."));
                } else {
                    logMsg("✗ Ошибка: " + err);
                    QMessageBox::critical(this, L::q("Ошибка","Error"), err);
                }
                work_->deleteLater(); work_ = nullptr;
            }, Qt::QueuedConnection);
            work_->start();
        });

        // Verify button
        connect(verBtn, &QPushButton::clicked, [=]() {
            const QString expected = expectedEdit->text().trimmed().toLower();
            if (expected.isEmpty()) {
                verResult->setText("Введите ожидаемую контрольную сумму.");
                verResult->setStyleSheet("color:#f97316;font-size:12px;");
                return;
            }
            const QString sha256 = sha256Display->text().toLower();
            const QString blake2 = blake2Display->text().toLower();
            if (sha256.isEmpty() && blake2.isEmpty()) {
                verResult->setText("Сначала вычислите хэши файла.");
                verResult->setStyleSheet("color:#f97316;font-size:12px;");
                return;
            }
            if (expected == sha256) {
                verResult->setText("✓ SHA-256 совпадает — файл не изменён.");
                verResult->setStyleSheet("color:#22c55e;font-weight:700;font-size:13px;");
            } else if (expected == blake2) {
                verResult->setText("✓ BLAKE2b-512 совпадает — файл не изменён.");
                verResult->setStyleSheet("color:#22c55e;font-weight:700;font-size:13px;");
            } else {
                verResult->setText("✗ Ни один хэш не совпал. Файл мог быть изменён.");
                verResult->setStyleSheet("color:#ef4444;font-weight:700;font-size:13px;");
            }
        });

        return w;
    }

    // ── 09  Генератор паролей ─────────────────────────────────────────────────
    QWidget* makePasswordGenTab() {
        auto* w    = new QWidget;
        auto* vlay = new QVBoxLayout(w);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(0,0,0,0); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("09  Генератор паролей","09  Password Gen"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); vlay->addWidget(row); }
        auto* subLbl = new QLabel(L::q("Криптографически стойкая генерация паролей","Cryptographically secure password generation"));
        subLbl->setStyleSheet("font-size:12px;color:#7f8090;");
        vlay->addWidget(subLbl);

        auto* form = new QFormLayout;
        form->setSpacing(10); form->setContentsMargins(0, 8, 0, 0);
        form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
        form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        vlay->addLayout(form);

        auto* lengthSpin = new QSpinBox;
        lengthSpin->setRange(8, 128);
        lengthSpin->setValue(20);
        lengthSpin->setSuffix(L::q(" символов"," characters"));
        form->addRow(L::q("Длина:","Length:"), lengthSpin);

        auto* countSpin = new QSpinBox;
        countSpin->setRange(1, 20);
        countSpin->setValue(5);
        countSpin->setSuffix(L::q(" вариантов"," variants"));
        form->addRow(L::q("Количество:","Count:"), countSpin);

        auto* charsetRow = new QWidget;
        auto* charH = new QHBoxLayout(charsetRow);
        charH->setContentsMargins(0,0,0,0); charH->setSpacing(12);
        auto* chkLower  = new QCheckBox("a–z");  chkLower->setChecked(true);
        auto* chkUpper  = new QCheckBox("A–Z");  chkUpper->setChecked(true);
        auto* chkDigits = new QCheckBox("0–9");  chkDigits->setChecked(true);
        auto* chkSymbol = new QCheckBox("!@#…"); chkSymbol->setChecked(true);
        charH->addWidget(chkLower); charH->addWidget(chkUpper);
        charH->addWidget(chkDigits); charH->addWidget(chkSymbol);
        charH->addStretch(1);
        form->addRow(L::q("Символы:","Characters:"), charsetRow);

        auto* genBtn = makeActionBtn(L::q("  Сгенерировать","  Generate"), "#4f46e5", "#4338ca", "#a5b4fc");
        form->addRow("", genBtn);

        auto* resultList = new QListWidget;
        resultList->setFont(monoFont(11));
        resultList->setMinimumHeight(160);
        vlay->addWidget(resultList, 1);

        auto* btnRow = new QWidget;
        auto* btnH   = new QHBoxLayout(btnRow);
        btnH->setContentsMargins(0,0,0,0); btnH->setSpacing(8);
        auto* copySelBtn = new QPushButton("Копировать выбранный");
        auto* copyAllBtn = new QPushButton(L::q("Копировать все","Copy all"));
        btnH->addWidget(copySelBtn); btnH->addWidget(copyAllBtn); btnH->addStretch(1);
        vlay->addWidget(btnRow);

        connect(genBtn, &QPushButton::clicked, w, [=]() {
            resultList->clear();
            static const QString LOWER  = "abcdefghijklmnopqrstuvwxyz";
            static const QString UPPER  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            static const QString DIGITS = "0123456789";
            static const QString SYMS   = "!@#$%^&*()-_=+[]{}|;:,.<>?";
            QString charset;
            if (chkLower->isChecked())  charset += LOWER;
            if (chkUpper->isChecked())  charset += UPPER;
            if (chkDigits->isChecked()) charset += DIGITS;
            if (chkSymbol->isChecked()) charset += SYMS;
            if (charset.isEmpty()) {
                QMessageBox::warning(w, L::q("Ошибка","Error"), "Выберите хотя бы один тип символов.");
                return;
            }
            const int len   = lengthSpin->value();
            const int count = countSpin->value();
            auto rng = QRandomGenerator::securelySeeded();
            for (int i = 0; i < count; ++i) {
                QString pw; pw.reserve(len);
                for (int j = 0; j < len; ++j)
                    pw += charset[static_cast<int>(rng.bounded(static_cast<quint32>(charset.size())))];
                resultList->addItem(pw);
            }
        });

        connect(copySelBtn, &QPushButton::clicked, [=]() {
            auto* item = resultList->currentItem();
            if (item) QApplication::clipboard()->setText(item->text());
        });

        connect(copyAllBtn, &QPushButton::clicked, [=]() {
            QStringList all;
            for (int i = 0; i < resultList->count(); ++i)
                all << resultList->item(i)->text();
            QApplication::clipboard()->setText(all.join('\n'));
        });

        return w;
    }


    // ── 11  История операций ─────────────────────────────────────────────────
    QWidget* makeHistoryTab() {
        auto* w    = new QWidget;
        auto* vlay = new QVBoxLayout(w);
        vlay->setContentsMargins(24, 20, 24, 20);
        vlay->setSpacing(10);

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(0,0,0,0); h->setSpacing(8);
          auto* titleLbl = new QLabel(L::q("11  История операций","11  History"));
          titleLbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(titleLbl, 1); vlay->addWidget(row); }
        auto* subLbl = new QLabel(L::q("Журнал всех операций шифрования и расшифрования","Log of all encryption and decryption operations"));
        subLbl->setStyleSheet("font-size:12px;color:#7f8090;");
        vlay->addWidget(subLbl);

        historyView_ = new QPlainTextEdit;
        historyView_->setReadOnly(true);
        historyView_->setFont(monoFont(10));
        historyView_->setStyleSheet(
            "QPlainTextEdit { background:#f7f8fb; border:1.5px solid #dddee5;"
            " border-radius:6px; padding:8px; color:#2e2f38; }");
        vlay->addWidget(historyView_, 1);

        const QStringList hist = QSettings("Cryptograf","Cryptograf").value("history").toStringList();
        historyView_->setPlainText(hist.join('\n'));

        auto* btnRow = new QWidget;
        auto* btnH   = new QHBoxLayout(btnRow);
        btnH->setContentsMargins(0,0,0,0); btnH->setSpacing(8);
        auto* clrBtn = new QPushButton(L::q("Очистить историю","Clear History"));
        btnH->addWidget(clrBtn); btnH->addStretch(1);
        vlay->addWidget(btnRow);

        connect(clrBtn, &QPushButton::clicked, this, [=, this]() {
            if (QMessageBox::question(this, L::q("Очистить историю","Clear History"),
                    "Очистить всю историю операций?") != QMessageBox::Yes) return;
            QSettings("Cryptograf","Cryptograf").remove("history");
            historyView_->clear();
            logMsg(L::q("✓ История операций очищена.","✓ History cleared."));
        });

        return w;
    }

    // ── 12  ИНФО — справка по всем вкладкам ──────────────────────────────────
    QWidget* makeHelpTab() {
        auto* w    = new QWidget;
        auto* vlay = new QVBoxLayout(w);
        vlay->setContentsMargins(0, 0, 0, 0);
        vlay->setSpacing(0);

        { auto* row = new QWidget; auto* h = new QHBoxLayout(row);
          h->setContentsMargins(24, 20, 24, 10); h->setSpacing(8);
          auto* lbl = new QLabel(L::q("12  ИНФО — Руководство пользователя","12  INFO — User Guide"));
          lbl->setStyleSheet("font-size:17px;font-weight:700;color:#2e2f38;");
          h->addWidget(lbl, 1); vlay->addWidget(row); }

        auto* browser = new QTextBrowser;
        browser->setOpenLinks(false);
        browser->setFrameShape(QFrame::NoFrame);

        // Document-level background
        {
            QTextFrameFormat ff;
            ff.setBackground(QColor("#f8f9fc"));
            browser->document()->rootFrame()->setFrameFormat(ff);
        }
        browser->setStyleSheet(
            "QTextBrowser { background:#f8f9fc; border:none; padding:0; }");

        static const char* const HTML = R"html(
<html><body style='font-family:sans-serif;font-size:13px;color:#2e2f38;
                   background:#f8f9fc;margin:0;padding:0 24px 32px 24px;'>

<!-- ── 01 Шифровать ─────────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>01 — Шифровать</h2>
<p>Шифрует файл или папку алгоритмом <b>AES-256</b> в выбранном режиме.
Результат сохраняется в файл <b>.enc</b>, содержащий зашифрованные данные
и заголовок со всеми параметрами.</p>

<p><b>Тип</b> — выберите <i>Файл</i> или <i>Папка</i>. При выборе папки
она упаковывается во временный архив (CDIR) и шифруется целиком.</p>

<p><b>Режим шифрования</b> — 11 вариантов AES-256:</p>
<ul>
<li><b>ECB</b> — простейший, без IV, детерминированный. Не рекомендуется для конфиденциальных данных.</li>
<li><b>CBC</b> — случайный IV, классический режим. Надёжен при уникальном IV.</li>
<li><b>CFB</b> — самосинхронизирующийся поточный режим на основе CBC.</li>
<li><b>OFB</b> — Output Feedback, ключевой поток не зависит от открытого текста.</li>
<li><b>CTR</b> — Counter Mode, параллелизуется, высокая скорость. Рекомендуется по умолчанию.</li>
<li><b>GCM</b> — AEAD, встроенная аутентификация (128-бит тег). Стандарт TLS.</li>
<li><b>CCM</b> — AEAD, аутентификация + шифрование за один проход.</li>
<li><b>GCM-SIV</b> — AEAD, стойкий к повторному использованию nonce (RFC 8452).</li>
<li><b>SIV</b> — Synthetic IV, нечувствителен к повторяющимся nonce.</li>
<li><b>EAX</b> — AEAD, простая конструкция, гибкий размер тега.</li>
<li><b>OCB</b> — AEAD, максимальная производительность (RFC 7253).</li>
</ul>
<p>Режимы <b>GCM, CCM, GCM-SIV, SIV, EAX, OCB</b> — это AEAD: они одновременно
шифруют и проверяют целостность. Остальные режимы используют HMAC-SHA256 (Encrypt-then-MAC).</p>

<p><b>Пароль</b> — произвольная строка. Индикатор надёжности оценивает энтропию
(4 уровня: очень слабый → надёжный). Поле «Подтверждение» должно совпасть.</p>

<p><b>Файл-ключ</b> — необязательный файл, содержимое которого добавляется к паролю
при выводе ключа. При расшифровке тот же файл обязателен.</p>

<p><b>KDF</b> — PBKDF2-HMAC-SHA256, <b>100 000 итераций</b>, соль 16 байт (случайная).
Выводит 256-битный ключ из пароля и опционального файл-ключа.</p>

<p><b>Безопасно удалить исходный файл</b> — после успешного шифрования исходный файл
перезаписывается случайными байтами перед удалением.</p>

<p>После шифрования блок <b>«Результат»</b> показывает первые байты шифртекста
и тег аутентификации (или HMAC) для визуальной проверки.</p>

<!-- ── 02 Расшифровать ───────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>02 — Расшифровать</h2>
<p>Расшифровывает файлы <b>.enc</b>, созданные вкладкой «Шифровать».</p>

<p><b>Режим определяется автоматически</b> из заголовка .enc файла — указывать вручную не нужно.</p>

<p><b>Зашифрованный файл</b> — выберите или перетащите .enc файл.
<b>Выходной файл/папка</b> — куда сохранить расшифрованное содержимое.
Если исходным был архив папки, результат сохраняется в указанную директорию.</p>

<p><b>Пароль</b> — тот же, что использовался при шифровании.
<b>Файл-ключ</b> — тот же файл-ключ, если он применялся при шифровании.</p>

<p>Для AEAD-режимов целостность проверяется автоматически: если данные изменены,
расшифровка прерывается с ошибкой. Для остальных режимов проверяется HMAC-SHA256.</p>

<!-- ── 03 Подпись ───────────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>03 — Подпись (ECDSA P-256)</h2>
<p>Цифровая подпись файлов на основе <b>ECDSA P-256</b> (secp256r1, NIST).</p>

<p><b>Генерация ключевой пары</b> — укажите пути для сохранения закрытого и открытого ключей,
затем нажмите «Сгенерировать ключи». Закрытый ключ хранится в PEM-формате,
открытый — также в PEM. <b>Никогда не передавайте закрытый ключ другим лицам.</b></p>

<p><b>Подписать файл</b> — выберите файл и файл закрытого ключа.
Нажмите «Подписать» — будет создан файл подписи <b>.sig</b> (двоичный формат DER).
Путь к .sig файлу заполняется автоматически при выборе входного файла.</p>

<p><b>Проверить подпись</b> — укажите исходный файл, файл подписи (.sig)
и файл открытого ключа. Нажмите «Проверить подпись».
Результат: подпись <b>верна</b> (файл не изменён) или <b>недействительна</b>
(файл изменён или использован другой ключ).</p>

<!-- ── 04 Информация ────────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>04 — Информация (.enc)</h2>
<p>Разбирает заголовок зашифрованного файла и отображает все метаданные.</p>

<p>Выберите или перетащите <b>.enc файл</b> в поле. Информация обновляется немедленно:</p>
<ul>
<li><b>Тип</b> — Файл или Архив папки (CDIR).</li>
<li><b>Режим</b> — алгоритм AES-256 (например AES-256-CTR).</li>
<li><b>AEAD</b> — да/нет (аутентифицированное шифрование).</li>
<li><b>Шифртекст</b> — размер зашифрованных данных в байтах.</li>
<li><b>Соль</b> — 16 байт в hex, случайная, используется в PBKDF2.</li>
<li><b>IV / Nonce</b> — 16 байт в hex, случайный вектор инициализации.</li>
<li><b>Тег AEAD / HMAC-SHA256</b> — тег аутентификации или HMAC для проверки целостности.</li>
<li><b>KDF</b> — PBKDF2-HMAC-SHA256, количество итераций.</li>
<li><b>Целостность</b> — метод защиты от подделки.</li>
</ul>

<!-- ── 05 Пакет ─────────────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>05 — Пакетное шифрование</h2>
<p>Шифрует или расшифровывает <b>несколько файлов за один раз</b> с единым паролем и режимом.</p>

<p><b>Список файлов</b> — добавьте файлы кнопкой «Добавить файлы…» или перетащите их.
«Удалить выбранные» убирает отмеченные файлы из списка. Каждый файл обрабатывается независимо.</p>

<p><b>Режим</b> и <b>Пароль</b> — применяются ко всем файлам в списке одинаково.</p>

<p><b>Зашифровать всё</b> — создаёт рядом с каждым исходным файлом файл <b>.enc</b>.
<b>Расшифровать всё</b> — для каждого файла в списке убирает суффикс .enc.</p>

<p>Прогресс и результат каждой операции отображаются в нижней строке лога.</p>

<!-- ── 06 Заметки ───────────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>06 — Заметки (шифрование текста)</h2>
<p>Шифрует и расшифровывает произвольный текст <b>без создания временных файлов на диске</b>.
Данные существуют только в памяти.</p>

<p><b>Текст</b> — введите или вставьте текст в большое поле.
<b>Режим</b> — выберите режим AES-256 (все 11 режимов доступны).
<b>Пароль</b> — ключ шифрования.</p>

<p><b>Зашифровать</b> — преобразует текст в Base64-строку зашифрованного .enc блока и отображает в том же поле.</p>
<p><b>Расшифровать</b> — принимает Base64-строку и возвращает исходный текст.</p>
<p><b>Очистить</b> — немедленно стирает содержимое поля из памяти.</p>

<!-- ── 07 Настройки ─────────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>07 — Настройки</h2>
<p>Параметры приложения, сохраняемые между сессиями (QSettings).</p>
<ul>
<li><b>Тёмная тема</b> — переключает интерфейс между светлым и тёмным оформлением.
Изменение применяется мгновенно.</li>
<li><b>Режим по умолчанию</b> — режим AES-256, выбираемый при открытии вкладки «Шифровать».
По умолчанию — CTR.</li>
</ul>

<!-- ── 08 Целостность ───────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>08 — Целостность (хэш-суммы)</h2>
<p>Вычисляет и проверяет контрольные суммы файлов.</p>

<p>Выберите файл, нажмите <b>«Вычислить хэши»</b>. Будут показаны:</p>
<ul>
<li><b>SHA-256</b> — 256 бит (64 hex-символа), стандарт NIST. Широко используется.</li>
<li><b>BLAKE2b-512</b> — 512 бит (128 hex-символов), быстрее SHA-256, высокая стойкость.</li>
</ul>

<p>Оба значения можно скопировать кнопкой 📋 рядом с полем.</p>

<p><b>Проверить контрольную сумму</b> — вставьте известный хэш в поле «Ожидаемый хэш».
Алгоритм определяется автоматически по длине строки (64 символа → SHA-256, 128 → BLAKE2b-512).
Нажмите «Проверить» — результат: <span style='color:green'><b>совпадает</b></span>
или <span style='color:red'><b>не совпадает</b></span>.</p>

<!-- ── 09 Генератор ─────────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>09 — Генератор паролей</h2>
<p>Генерирует криптографически стойкие пароли с использованием
<b>QRandomGenerator::global()</b> (CSPRNG операционной системы).</p>

<p><b>Длина</b> — от 8 до 128 символов.
<b>Количество</b> — от 1 до 20 вариантов одновременно.
<b>Символы</b> — выберите группы:</p>
<ul>
<li><b>a–z</b> — 26 строчных латинских букв</li>
<li><b>A–Z</b> — 26 прописных латинских букв</li>
<li><b>0–9</b> — 10 цифр</li>
<li><b>!@#…</b> — специальные символы: <code>!@#$%^&amp;*()-_=+[]{}|;:,./&lt;&gt;?</code></li>
</ul>
<p>Минимум одна группа должна быть выбрана. Нажмите <b>«Сгенерировать»</b> —
пароли появятся в списке. Двойной щелчок или кнопка «Копировать» копирует пароль в буфер обмена.
«Копировать все» копирует все варианты, разделённые переносом строки.</p>

<!-- ── 11 История ───────────────────────────────────────────────────────── -->
<h2 style='color:#4f46e5;border-bottom:2px solid #4f46e5;padding-bottom:4px;
           margin-top:24px;'>11 — История операций</h2>
<p>Журнал всех операций шифрования и расшифрования, выполненных в текущей и прошлых сессиях.</p>

<p>Каждая запись содержит:</p>
<ul>
<li><b>Дату и время</b> операции.</li>
<li><b>Тип операции</b> — Шифрование, Расшифрование, Шифрование папки и т.д.</li>
<li><b>Путь к выходному файлу</b> — куда был сохранён результат.</li>
<li><b>Режим AES-256</b> — использованный алгоритм.</li>
</ul>

<p>История хранится в <b>QSettings</b> (реестр или конфиг-файл в зависимости от ОС)
и сохраняется между запусками приложения. Максимум 500 записей.</p>

<p><b>Очистить историю</b> — удаляет все записи после подтверждения.
История не содержит паролей, ключей или содержимого файлов.</p>

<br>
<p style='color:#7f8090;font-size:11px;border-top:1px solid #dddee5;padding-top:8px;'>
Cryptograf — AES-256 · PBKDF2-HMAC-SHA256 · ECDSA P-256</p>
</body></html>
)html";

        browser->setHtml(QString::fromUtf8(HTML));
        // Re-apply background after setHtml()
        {
            QTextFrameFormat ff;
            ff.setBackground(QColor("#f8f9fc"));
            browser->document()->rootFrame()->setFrameFormat(ff);
        }

        vlay->addWidget(browser, 1);
        return w;
    }

    void retranslateUi() {
        // Language is baked into all widgets at construction (via L::q()).
        // Only update the window title here — it's not inside a tab function.
        setWindowTitle(L::en() ? "Cryptograf — AES-256 Encryption"
                                : "Cryptograf — AES-256");
    }

public:
    explicit CryptografWindow(QWidget* parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("Cryptograf — AES-256");
        resize(1200, 720);
        setMinimumSize(820, 540);
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

        tabs_ = new QTabWidget;
        auto* tabs = tabs_;
        tabs->setDocumentMode(true);
        tabs->tabBar()->setExpanding(false);
        tabs->addTab(makeEncryptTab(),  L::q("01  Шифровать","01  Encrypt"));
        tabs->addTab(makeDecryptTab(),  L::q("02  Расшифровать","02  Decrypt"));
        tabs->addTab(makeSignTab(),     L::q("03  Подпись","03  Sign"));
        tabs->addTab(makeInfoTab(),     L::q("04  Информация","04  File Info"));
        tabs->addTab(makeBatchTab(),    "05  Пакет");
        tabs->addTab(makeNotesTab(),    L::q("06  Заметки","06  Notes"));
        tabs->addTab(makeSettingsTab(), L::q("07  Настройки","07  Settings"));
        tabs->addTab(makeHashTab(),        L::q("08  Целостность","08  Integrity"));
        tabs->addTab(makePasswordGenTab(), "09  Генератор");
        tabs->addTab(makeHistoryTab(),     "11  История");
        tabs->addTab(makeHelpTab(),        "12  ИНФО");
        retranslateUi();
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
        statusBar()->showMessage(L::q("Готово.","Done."));
        logMsg("Cryptograf запущен. Режимы: ECB, CBC, CFB, OFB, CTR, GCM, CCM, GCM-SIV, SIV, EAX, OCB.");
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
