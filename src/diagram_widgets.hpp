#pragma once
#include <QWidget>
#include <QSvgRenderer>
#include <QPainter>
#include <QString>
#include "aes_cipher.hpp"

// ── Static SVG widget ─────────────────────────────────────────────────────────
class StaticSvgDiagram : public QWidget {
public:
    explicit StaticSvgDiagram(const QString& resource, QWidget* p = nullptr)
        : QWidget(p), m_renderer(resource)
    {
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        setMinimumSize(400, 300);
    }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.fillRect(rect(), Qt::white);
        if (!m_renderer.isValid()) return;
        QSizeF sz = m_renderer.defaultSize();
        if (sz.isEmpty()) { m_renderer.render(&painter, QRectF(rect())); return; }
        qreal scale = qMin(width() / sz.width(), height() / sz.height());
        qreal w = sz.width() * scale, h = sz.height() * scale;
        m_renderer.render(&painter, QRectF((width()-w)/2.0, (height()-h)/2.0, w, h));
    }
private:
    QSvgRenderer m_renderer;
};

// ── Dynamic encrypt diagram ───────────────────────────────────────────────────
class EncryptDiagramWidget : public QWidget {
    crypto::Mode m_mode = crypto::Mode::CTR;
    QSvgRenderer m_renderer;

    static QString matrixRow(const QString& label, const QString& active,
                             bool iv, bool a, bool par, bool last,
                             const QString& desc, int y)
    {
        const bool isActive = (label == "GCM/CCM")     ? (active == "GCM" || active == "CCM")
                            : (label == "SIV")          ? (active == "SIV" || active == "GCM-SIV")
                            : (label == "CBC/CFB/OFB")  ? (active == "CBC" || active == "CFB" || active == "OFB")
                            :                              (label == active);
        const QString lc = isActive ? (a ? "#4f46e5" : "#d97706") : "#374151";
        const QString bg = isActive ? (a ? "#eef2ff" : "#fffbeb") : QString();
        QString row;
        if (isActive && !bg.isEmpty())
            row += "<rect x=\"16\" y=\"" + QString::number(y-14) +
                   "\" width=\"548\" height=\"19\" fill=\"" + bg + "\"/>";
        const QString yS = QString::number(y);
        auto check = [](bool v){ return v ? QString("✓") : QString("✗"); };
        auto cc    = [](bool v){ return v ? QStringLiteral("#16a34a") : QStringLiteral("#dc2626"); };
        row += "<text x=\"62\"  y=\"" + yS + "\" font-size=\"9\" fill=\"" + lc +
               "\" text-anchor=\"middle\" font-weight=\"700\">" + label + "</text>"
               "<text x=\"140\" y=\"" + yS + "\" font-size=\"9\" fill=\"" + cc(iv) +
               "\" text-anchor=\"middle\">" + check(iv) + "</text>"
               "<text x=\"220\" y=\"" + yS + "\" font-size=\"9\" fill=\"" + cc(a) +
               "\" text-anchor=\"middle\">" + check(a) + "</text>"
               "<text x=\"310\" y=\"" + yS + "\" font-size=\"9\" fill=\"" + cc(par) +
               "\" text-anchor=\"middle\">" + check(par) + "</text>"
               "<text x=\"430\" y=\"" + yS + "\" font-size=\"8.5\" fill=\"#64748b\""
               " text-anchor=\"middle\" clip-path=\"url(#descClip)\">" + desc + "</text>";
        if (!last)
            row += "<line x1=\"28\" y1=\"" + QString::number(y+6) +
                   "\" x2=\"552\" y2=\"" + QString::number(y+6) +
                   "\" stroke=\"#f1f5f9\" stroke-width=\"1\"/>";
        return row;
    }

    static QString buildSvg(crypto::Mode mode) {
        const bool aead    = crypto::mode_is_aead(mode);
        const bool needsIv = crypto::mode_needs_iv(mode);
        const QString modeN = QString::fromStdString(crypto::mode_to_string(mode));

        // tag section colors
        const QString tagFill   = aead ? "#16a34a"  : "#d97706";
        const QString tagLabel  = aead ? "16B AEAD" : "32B HMAC";
        const QString ivOpacity = needsIv ? "1" : "0.25";
        const QString ivLine    = needsIv ? "+ IV / nonce" : "без IV";
        const QString modeColor = aead ? "#a78bfa" : "#94a3b8";

        // IV badge
        const QString ivBadgeFill = needsIv ? "#dbeafe" : "#f1f5f9";
        const QString ivBadgeText = needsIv ? "#1d4ed8" : "#94a3b8";
        const QString ivBadgeLbl  = needsIv ? "IV 16B (random)"
                                   : (mode == crypto::Mode::ECB ? "нет IV (ECB)"
                                                                 : "нет nonce (SIV)");

        // AEAD/Non-AEAD box highlight
        const QString aeadBg   = aead ? "#f0fdf4" : "#f8fafc";
        const QString aeadBdr  = aead ? "#16a34a" : "#e2e8f0";
        const QString aeadBdrW = aead ? "2.5" : "1.5";
        const QString aeadHdr  = aead ? "#16a34a" : "#94a3b8";
        const QString aeadTxt  = aead ? "#166534" : "#94a3b8";

        const QString nonaBg   = !aead ? "#fff7ed"  : "#f8fafc";
        const QString nonaBdr  = !aead ? "#d97706"  : "#e2e8f0";
        const QString nonaBdrW = !aead ? "2.5" : "1.5";
        const QString nonaHdr  = !aead ? "#d97706" : "#94a3b8";
        const QString nonaTxt  = !aead ? "#92400e" : "#94a3b8";

        // matrix rows
        const QString rows =
            matrixRow("ECB",         modeN, false, false, true,  false, "Нет IV, небезопасен",      333) +
            matrixRow("CBC/CFB/OFB", modeN, true,  false, false, false, "Послед., случайный IV",    350) +
            matrixRow("CTR",         modeN, true,  false, true,  false, "Параллелизуемый поток",    367) +
            matrixRow("GCM/CCM",     modeN, true,  true,  true,  false, "NIST AEAD, nonce 12B",     384) +
            matrixRow("EAX",         modeN, true,  true,  false, false, "CTR+OMAC AEAD, nonce 12B", 401) +
            matrixRow("OCB",         modeN, true,  true,  true,  false, "Парал. AEAD, nonce 12B",   418) +
            matrixRow("SIV",         modeN, false, true,  true,  true,  "Устойч. к повтору nonce",  435);

        QString svg;
        svg.reserve(8000);
        svg +=
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<svg viewBox=\"0 0 580 450\" xmlns=\"http://www.w3.org/2000/svg\""
            " font-family=\"Inter,system-ui,sans-serif\">"
            "<defs>"
            "<marker id=\"arr\" markerWidth=\"8\" markerHeight=\"8\" refX=\"7\" refY=\"3.5\" orient=\"auto\">"
            "<path d=\"M0,0 L8,3.5 L0,7 Z\" fill=\"#94a3b8\"/></marker>"
            "<filter id=\"shadow\" x=\"-5%\" y=\"-5%\" width=\"110%\" height=\"115%\">"
            "<feDropShadow dx=\"0\" dy=\"1\" stdDeviation=\"2\" flood-color=\"#00000018\"/>"
            "</filter>"
            "<clipPath id=\"descClip\">"
            "<rect x=\"355\" y=\"318\" width=\"210\" height=\"128\"/>"
            "</clipPath>"
            "</defs>"

            // FILE FORMAT STRIP
            "<text x=\"16\" y=\"20\" font-size=\"9\" fill=\"#94a3b8\" font-weight=\"700\""
            " letter-spacing=\"1.2\">ФОРМАТ ФАЙЛА  .enc</text>"
            "<rect x=\"16\" y=\"28\" width=\"548\" height=\"32\" rx=\"6\" fill=\"white\""
            " stroke=\"#e2e8f0\" stroke-width=\"1\"/>"
            "<rect x=\"16\" y=\"28\" width=\"52\" height=\"32\" rx=\"6\" fill=\"#4f46e5\"/>"
            "<text x=\"42\" y=\"48\" font-size=\"8.5\" fill=\"white\" text-anchor=\"middle\""
            " font-weight=\"700\">magic</text>"
            "<text x=\"42\" y=\"56\" font-size=\"7\" fill=\"#c7d2fe\" text-anchor=\"middle\">AES 4B</text>"
            "<rect x=\"69\" y=\"28\" width=\"30\" height=\"32\" fill=\"#7c3aed\"/>"
            "<text x=\"84\" y=\"47\" font-size=\"8.5\" fill=\"white\" text-anchor=\"middle\""
            " font-weight=\"700\">mode</text>"
            "<text x=\"84\" y=\"56\" font-size=\"7\" fill=\"#ddd6fe\" text-anchor=\"middle\">1B</text>"
            "<rect x=\"100\" y=\"28\" width=\"80\" height=\"32\" fill=\"#0369a1\"/>"
            "<text x=\"140\" y=\"47\" font-size=\"8.5\" fill=\"white\" text-anchor=\"middle\""
            " font-weight=\"700\">salt</text>"
            "<text x=\"140\" y=\"56\" font-size=\"7\" fill=\"#bae6fd\""
            " text-anchor=\"middle\">16B off 5</text>"
            "<rect x=\"181\" y=\"28\" width=\"84\" height=\"32\" fill=\"#0284c7\" opacity=\"" + ivOpacity + "\"/>"
            "<text x=\"223\" y=\"47\" font-size=\"8.5\" fill=\"white\" text-anchor=\"middle\""
            " font-weight=\"700\" opacity=\"" + ivOpacity + "\">iv / nonce</text>"
            "<text x=\"223\" y=\"56\" font-size=\"7\" fill=\"#bae6fd\" text-anchor=\"middle\""
            " opacity=\"" + ivOpacity + "\">16B off 21</text>"
            "<rect x=\"266\" y=\"28\" width=\"222\" height=\"32\" fill=\"#334155\"/>"
            "<text x=\"377\" y=\"47\" font-size=\"8.5\" fill=\"#cbd5e1\""
            " text-anchor=\"middle\" font-weight=\"700\">ciphertext</text>"
            "<text x=\"377\" y=\"56\" font-size=\"7\" fill=\"#94a3b8\""
            " text-anchor=\"middle\">N байт off 37</text>"
            "<rect x=\"489\" y=\"28\" width=\"75\" height=\"32\" rx=\"6\" fill=\"" + tagFill + "\"/>"
            "<text x=\"527\" y=\"47\" font-size=\"8.5\" fill=\"white\" text-anchor=\"middle\""
            " font-weight=\"700\">tag</text>"
            "<text x=\"527\" y=\"56\" font-size=\"7\" fill=\"white\""
            " text-anchor=\"middle\" opacity=\"0.85\">" + tagLabel + "</text>"

            // PIPELINE
            "<text x=\"16\" y=\"84\" font-size=\"9\" fill=\"#94a3b8\" font-weight=\"700\""
            " letter-spacing=\"1.2\">КОНВЕЙЕР ШИФРОВАНИЯ</text>"
            "<rect x=\"16\" y=\"92\" width=\"82\" height=\"54\" rx=\"8\" fill=\"white\""
            " stroke=\"#e2e8f0\" stroke-width=\"1.5\" filter=\"url(#shadow)\"/>"
            "<text x=\"57\" y=\"113\" font-size=\"8.5\" fill=\"#94a3b8\""
            " text-anchor=\"middle\">Входной</text>"
            "<text x=\"57\" y=\"127\" font-size=\"13\" fill=\"#1e293b\""
            " text-anchor=\"middle\" font-weight=\"700\">Файл</text>"
            "<text x=\"57\" y=\"140\" font-size=\"7.5\" fill=\"#94a3b8\""
            " text-anchor=\"middle\">plaintext</text>"
            "<line x1=\"98\" y1=\"119\" x2=\"120\" y2=\"119\" stroke=\"#94a3b8\""
            " stroke-width=\"1.5\" marker-end=\"url(#arr)\"/>"
            "<rect x=\"121\" y=\"92\" width=\"100\" height=\"54\" rx=\"8\" fill=\"#eef2ff\""
            " stroke=\"#6366f1\" stroke-width=\"1.5\" filter=\"url(#shadow)\"/>"
            "<text x=\"171\" y=\"113\" font-size=\"9.5\" fill=\"#4f46e5\""
            " text-anchor=\"middle\" font-weight=\"700\">PBKDF2</text>"
            "<text x=\"171\" y=\"126\" font-size=\"8\" fill=\"#6366f1\""
            " text-anchor=\"middle\">HMAC-SHA256</text>"
            "<text x=\"171\" y=\"138\" font-size=\"7.5\" fill=\"#818cf8\""
            " text-anchor=\"middle\">100 000 итераций</text>"
            "<rect x=\"131\" y=\"150\" width=\"80\" height=\"16\" rx=\"8\" fill=\"#dbeafe\"/>"
            "<text x=\"171\" y=\"162\" font-size=\"7.5\" fill=\"#1d4ed8\""
            " text-anchor=\"middle\">соль 16B (random)</text>"
            "<line x1=\"221\" y1=\"119\" x2=\"244\" y2=\"119\" stroke=\"#94a3b8\""
            " stroke-width=\"1.5\" marker-end=\"url(#arr)\"/>"
            "<rect x=\"245\" y=\"92\" width=\"108\" height=\"54\" rx=\"8\" fill=\"#eef2ff\""
            " stroke=\"#6366f1\" stroke-width=\"1.5\" filter=\"url(#shadow)\"/>"
            "<text x=\"299\" y=\"110\" font-size=\"9\" fill=\"#4f46e5\""
            " text-anchor=\"middle\" font-weight=\"700\">64 байта ключей</text>"
            "<text x=\"299\" y=\"124\" font-size=\"8\" fill=\"#555666\""
            " text-anchor=\"middle\">enc[0..31] AES-256</text>"
            "<text x=\"299\" y=\"137\" font-size=\"8\" fill=\"#555666\""
            " text-anchor=\"middle\">mac[32..63] HMAC</text>"
            "<line x1=\"353\" y1=\"119\" x2=\"376\" y2=\"119\" stroke=\"#94a3b8\""
            " stroke-width=\"1.5\" marker-end=\"url(#arr)\"/>"
            "<rect x=\"377\" y=\"92\" width=\"86\" height=\"54\" rx=\"8\" fill=\"#1e293b\""
            " stroke=\"#334155\" stroke-width=\"1.5\" filter=\"url(#shadow)\"/>"
            "<text x=\"420\" y=\"112\" font-size=\"9.5\" fill=\"#e2e8f0\""
            " text-anchor=\"middle\" font-weight=\"700\">AES-256</text>"
            "<text x=\"420\" y=\"126\" font-size=\"9.5\" fill=\"" + modeColor + "\""
            " text-anchor=\"middle\" font-weight=\"700\">" + modeN + "</text>"
            "<text x=\"420\" y=\"139\" font-size=\"7.5\" fill=\"#64748b\""
            " text-anchor=\"middle\">" + ivLine + "</text>"
            "<line x1=\"463\" y1=\"119\" x2=\"486\" y2=\"119\" stroke=\"#94a3b8\""
            " stroke-width=\"1.5\" marker-end=\"url(#arr)\"/>"
            "<rect x=\"487\" y=\"92\" width=\"77\" height=\"54\" rx=\"8\" fill=\"white\""
            " stroke=\"#e2e8f0\" stroke-width=\"1.5\" filter=\"url(#shadow)\"/>"
            "<text x=\"526\" y=\"113\" font-size=\"8.5\" fill=\"#94a3b8\""
            " text-anchor=\"middle\">Выходной</text>"
            "<text x=\"526\" y=\"127\" font-size=\"13\" fill=\"#1e293b\""
            " text-anchor=\"middle\" font-weight=\"700\">.enc</text>"
            "<text x=\"526\" y=\"140\" font-size=\"7.5\" fill=\"#94a3b8\""
            " text-anchor=\"middle\">файл</text>"
            "<rect x=\"377\" y=\"150\" width=\"86\" height=\"16\" rx=\"8\" fill=\"" + ivBadgeFill + "\"/>"
            "<text x=\"420\" y=\"162\" font-size=\"7.5\" fill=\"" + ivBadgeText + "\""
            " text-anchor=\"middle\">" + ivBadgeLbl + "</text>"

            // AUTH MODES
            "<text x=\"16\" y=\"190\" font-size=\"9\" fill=\"#94a3b8\" font-weight=\"700\""
            " letter-spacing=\"1.2\">АУТЕНТИФИКАЦИЯ</text>"
            "<rect x=\"16\" y=\"198\" width=\"268\" height=\"68\" rx=\"8\" fill=\"" + aeadBg +
            "\" stroke=\"" + aeadBdr + "\" stroke-width=\"" + aeadBdrW +
            "\" filter=\"url(#shadow)\"/>"
            "<rect x=\"16\" y=\"198\" width=\"268\" height=\"22\" rx=\"8\" fill=\"" + aeadHdr + "\"/>"
            "<rect x=\"16\" y=\"208\" width=\"268\" height=\"12\" fill=\"" + aeadHdr + "\"/>"
            "<text x=\"150\" y=\"213\" font-size=\"9.5\" fill=\"white\""
            " text-anchor=\"middle\" font-weight=\"700\">AEAD (GCM, CCM, GCM-SIV, SIV)</text>"
            "<text x=\"32\" y=\"234\" font-size=\"8.5\" fill=\"" + aeadTxt + "\">- Шифрование и аутентификация совмещены</text>"
            "<text x=\"32\" y=\"248\" font-size=\"8.5\" fill=\"" + aeadTxt + "\">- Тег аутентификации 16 байт</text>"
            "<text x=\"32\" y=\"261\" font-size=\"8.5\" fill=\"" + aeadTxt + "\">- Встроен в конец файла</text>"
            "<rect x=\"296\" y=\"198\" width=\"268\" height=\"68\" rx=\"8\" fill=\"" + nonaBg +
            "\" stroke=\"" + nonaBdr + "\" stroke-width=\"" + nonaBdrW +
            "\" filter=\"url(#shadow)\"/>"
            "<rect x=\"296\" y=\"198\" width=\"268\" height=\"22\" rx=\"8\" fill=\"" + nonaHdr + "\"/>"
            "<rect x=\"296\" y=\"208\" width=\"268\" height=\"12\" fill=\"" + nonaHdr + "\"/>"
            "<text x=\"430\" y=\"213\" font-size=\"9.5\" fill=\"white\""
            " text-anchor=\"middle\" font-weight=\"700\">Non-AEAD (ECB, CBC, CFB, OFB, CTR)</text>"
            "<text x=\"312\" y=\"234\" font-size=\"8.5\" fill=\"" + nonaTxt + "\">- Encrypt-then-MAC: HMAC-SHA256</text>"
            "<text x=\"312\" y=\"248\" font-size=\"8.5\" fill=\"" + nonaTxt + "\">- Охватывает header + ciphertext</text>"
            "<text x=\"312\" y=\"261\" font-size=\"8.5\" fill=\"" + nonaTxt + "\">- Тег 32 байта в конце файла</text>"

            // MODE MATRIX
            "<text x=\"16\" y=\"288\" font-size=\"9\" fill=\"#94a3b8\" font-weight=\"700\""
            " letter-spacing=\"1.2\">МАТРИЦА РЕЖИМОВ</text>"
            "<rect x=\"16\" y=\"296\" width=\"548\" height=\"150\" rx=\"8\" fill=\"white\""
            " stroke=\"#e2e8f0\" stroke-width=\"1\" filter=\"url(#shadow)\"/>"
            "<rect x=\"16\" y=\"296\" width=\"548\" height=\"22\" rx=\"8\" fill=\"#f8fafc\"/>"
            "<rect x=\"16\" y=\"306\" width=\"548\" height=\"12\" fill=\"#f8fafc\"/>"
            "<line x1=\"16\" y1=\"318\" x2=\"564\" y2=\"318\" stroke=\"#e2e8f0\" stroke-width=\"1\"/>"
            "<text x=\"62\"  y=\"311\" font-size=\"8.5\" fill=\"#64748b\""
            " text-anchor=\"middle\" font-weight=\"700\">Режим</text>"
            "<text x=\"140\" y=\"311\" font-size=\"8.5\" fill=\"#64748b\""
            " text-anchor=\"middle\" font-weight=\"700\">IV / Nonce</text>"
            "<text x=\"220\" y=\"311\" font-size=\"8.5\" fill=\"#64748b\""
            " text-anchor=\"middle\" font-weight=\"700\">AEAD</text>"
            "<text x=\"310\" y=\"311\" font-size=\"8.5\" fill=\"#64748b\""
            " text-anchor=\"middle\" font-weight=\"700\">Параллель</text>"
            "<text x=\"430\" y=\"311\" font-size=\"8.5\" fill=\"#64748b\""
            " text-anchor=\"middle\" font-weight=\"700\">Описание</text>" +
            rows +
            "</svg>";
        return svg;
    }

public:
    explicit EncryptDiagramWidget(QWidget* p = nullptr) : QWidget(p) {
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        setMinimumSize(400, 350);
        m_renderer.load(buildSvg(m_mode).toUtf8());
    }

public:
    void setMode(crypto::Mode m) {
        if (m_mode == m) return;
        m_mode = m;
        m_renderer.load(buildSvg(m).toUtf8());
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.fillRect(rect(), Qt::white);
        if (!m_renderer.isValid()) return;
        QSizeF sz = m_renderer.defaultSize();
        if (sz.isEmpty()) { m_renderer.render(&painter, QRectF(rect())); return; }
        qreal scale = qMin(width() / sz.width(), height() / sz.height());
        qreal w = sz.width() * scale, h = sz.height() * scale;
        m_renderer.render(&painter, QRectF((width()-w)/2.0, (height()-h)/2.0, w, h));
    }
};
