import { jsPDF } from "jspdf";
import type { Finding, Scan, Severity } from "../types";

const W = 210;
const H = 297;
const M = 18;
const CONTENT_W = W - M * 2;

const C = {
  midnight: [5, 7, 17] as const,
  deep: [10, 16, 32] as const,
  royal: [11, 91, 107] as const,
  lavender: [0, 180, 210] as const,
  lilac: [169, 190, 219] as const,
  gold: [255, 45, 141] as const,
  paper: [245, 247, 253] as const,
  ink: [11, 22, 38] as const,
  muted: [89, 108, 130] as const,
  line: [207, 220, 234] as const,
  code: [238, 244, 250] as const,
  critical: [200, 35, 63] as const,
  high: [190, 82, 24] as const,
  medium: [153, 111, 15] as const,
  low: [20, 110, 135] as const,
  good: [22, 122, 93] as const,
};

const severityColor: Record<Severity, readonly [number, number, number]> = {
  critical: C.critical,
  high: C.high,
  medium: C.medium,
  low: C.low,
  informational: C.muted,
};

function clean(value: string): string {
  return value
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\u2192/g, "->")
    .replace(/\u00b7/g, "-")
    .replace(/\u2026/g, "...")
    .replace(/\u00a0/g, " ");
}

function dateLabel(iso: string): string {
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

function hostname(target: string): string {
  try {
    return new URL(target).host;
  } catch {
    return target.replace(/^https?:\/\//, "");
  }
}

function fill(doc: jsPDF, color: readonly [number, number, number]) {
  doc.setFillColor(color[0], color[1], color[2]);
}

function stroke(doc: jsPDF, color: readonly [number, number, number]) {
  doc.setDrawColor(color[0], color[1], color[2]);
}

function ink(doc: jsPDF, color: readonly [number, number, number]) {
  doc.setTextColor(color[0], color[1], color[2]);
}

function label(
  doc: jsPDF,
  text: string,
  x: number,
  y: number,
  color: readonly [number, number, number] = C.muted,
  size = 7,
  align: "left" | "right" = "left",
) {
  doc.setFont("helvetica", "bold");
  doc.setFontSize(size);
  ink(doc, color);
  doc.setCharSpace(0.35);
  doc.text(clean(text.toUpperCase()), x, y, { align });
  doc.setCharSpace(0);
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  return {
    critical: findings.filter((finding) => finding.severity === "critical").length,
    high: findings.filter((finding) => finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    low: findings.filter((finding) => finding.severity === "low").length,
    informational: findings.filter((finding) => finding.severity === "informational").length,
  };
}

function coverPage(doc: jsPDF, scan: Scan, findings: Finding[], generatedAt: Date) {
  fill(doc, C.midnight);
  doc.rect(0, 0, W, H, "F");

  // Command-centre edge markers: magenta header rail, cyan footer rail.
  fill(doc, C.gold);
  doc.rect(0, 0, W, 0.9, "F");
  fill(doc, C.lavender);
  doc.rect(0, H - 0.65, W, 0.65, "F");

  // Restrained editorial geometry - rings and a fine grid.
  stroke(doc, [18, 44, 64]);
  doc.setLineWidth(0.25);
  for (let x = 0; x <= W; x += 10) doc.line(x, 0, x, H);
  for (let y = 0; y <= H; y += 10) doc.line(0, y, W, y);

  fill(doc, [7, 16, 30]);
  doc.circle(174, 71, 66, "F");
  fill(doc, [9, 22, 40]);
  doc.circle(174, 71, 50, "F");
  stroke(doc, [16, 86, 104]);
  doc.setLineWidth(0.35);
  doc.circle(174, 71, 58, "S");
  doc.circle(174, 71, 42, "S");
  fill(doc, C.gold);
  doc.circle(174, 71, 1.4, "F");
  doc.setLineWidth(0.2);
  stroke(doc, [30, 130, 150]);
  doc.line(132, 71, 216, 71);
  doc.line(174, 31, 174, 111);

  // Custom hex/raven mark.
  const cx = 25;
  const cy = 24;
  const r = 6.2;
  const points: [number, number][] = [];
  for (let i = 0; i < 6; i += 1) {
    const angle = (Math.PI / 3) * i - Math.PI / 2;
    points.push([cx + Math.cos(angle) * r, cy + Math.sin(angle) * r]);
  }
  stroke(doc, C.lavender);
  doc.setLineWidth(0.55);
  for (let i = 0; i < 6; i += 1) {
    const next = points[(i + 1) % 6];
    doc.line(points[i][0], points[i][1], next[0], next[1]);
  }
  fill(doc, C.gold);
  doc.circle(cx, cy, 1.25, "F");

  label(doc, "BUG HUNTER LAB", 36, 22, C.paper, 10);
  label(doc, "Evidence-first security review", 36, 28, C.lilac, 7);

  const isSample = scan.dataSource === "sample";
  // Badge.
  stroke(doc, isSample ? C.gold : C.lavender);
  doc.setLineWidth(0.3);
  doc.roundedRect(W - M - 61, 18, 61, 9, 1.5, 1.5, "S");
  label(
    doc,
    isSample ? "SAMPLE DATA / DEMO REPORT" : "LIVE SCAN REPORT",
    W - M - 57.5,
    24,
    isSample ? C.gold : C.lavender,
    6.5,
  );

  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  ink(doc, C.lavender);
  doc.setCharSpace(0.8);
  doc.text("RAVENX 2026  /  PS-4  /  SECURITY EVIDENCE", M, 59);
  doc.setCharSpace(0);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(31);
  ink(doc, C.paper);
  doc.text("Security evidence", M, 91);
  doc.text("report", M, 104);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11.5);
  ink(doc, C.lilac);
  doc.text("A review of one authorised target,", M, 117);
  doc.text("with the observation behind every finding.", M, 123.5);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(7.5);
  ink(doc, C.gold);
  doc.setCharSpace(0.7);
  doc.text("DON'T JUST DETECT. PROVE. FIX. VERIFY.", M, 141);
  doc.setCharSpace(0);

  // Target block.
  fill(doc, [7, 14, 26]);
  stroke(doc, [24, 92, 108]);
  doc.setLineWidth(0.35);
  doc.roundedRect(M, 157, CONTENT_W, 39, 2, 2, "FD");
  fill(doc, C.gold);
  doc.rect(M, 157, 1.1, 39, "F");
  label(doc, "Target under review", M + 8, 167, C.lavender, 7);
  doc.setFont("courier", "bold");
  doc.setFontSize(21);
  ink(doc, C.paper);
  doc.text(clean(hostname(scan.target)), M + 8, 179);
  doc.setFont("courier", "normal");
  doc.setFontSize(7.5);
  ink(doc, C.lilac);
  doc.text(clean(scan.target), M + 8, 187);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(7);
  ink(doc, C.lavender);
  doc.text(scan.dataSource === "sample" ? "SAMPLE TARGET" : "AUTHORIZED TARGET", W - M - 8, 166.5, { align: "right" });

  // Metadata columns.
  const cols = [
    ["SCAN", scan.label],
    ["SCAN ID", scan.id],
    ["GENERATED", dateLabel(generatedAt.toISOString())],
    ["FINDINGS", String(findings.length)],
  ] as const;
  cols.forEach(([key, value], index) => {
    const x = M + index * 45;
    label(doc, key, x, 212, C.lavender, 6.2);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.2);
    ink(doc, C.paper);
    doc.text(clean(value), x, 218, { maxWidth: 40 });
  });

  stroke(doc, [24, 74, 90]);
  doc.setLineWidth(0.25);
  doc.line(M, 239, W - M, 239);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  ink(doc, C.lilac);
  if (scan.dataSource === "sample") {
    doc.text("This report is marked as illustrative sample data.", M, 249);
    doc.text("Do not treat sample data as a live security assessment.", M, 255);
  } else {
    doc.text("Generated from real SQLite scan records in BUG HUNTER LAB.", M, 249);
    doc.text("Absence of findings in scoped checks does not prove complete security.", M, 255);
  }

  label(doc, "RAVENX 2026  /  TEAM MASALA DOSA  /  GLA UNIVERSITY, MATHURA", M, 274, C.lavender, 6.2);
  label(doc, "BUG HUNTER LAB", W - M, 274, C.gold, 6.5, "right");
}

function createWriter(doc: jsPDF, initialLabel: string) {
  let y = 0;
  let currentLabel = initialLabel;

  function header(pageLabel: string) {
    fill(doc, C.paper);
    doc.rect(0, 0, W, H, "F");
    stroke(doc, C.line);
    doc.setLineWidth(0.25);
    doc.line(M, 16, W - M, 16);
    stroke(doc, C.royal);
    doc.setLineWidth(0.5);
    doc.line(M, 16, M + 22, 16);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    ink(doc, C.ink);
    doc.setCharSpace(0.35);
    doc.text("BUG HUNTER LAB", M, 11);
    doc.setCharSpace(0);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.8);
    ink(doc, C.muted);
    doc.text(clean(pageLabel.toUpperCase()), W - M, 11, { align: "right" });
    doc.setFont("courier", "normal");
    doc.setFontSize(6.5);
    ink(doc, C.muted);
  }

  function newPage(pageLabel = currentLabel) {
    currentLabel = pageLabel;
    doc.addPage();
    header(pageLabel);
    y = 28;
  }

  function ensure(height: number, pageLabel = currentLabel) {
    if (y + height > H - 19) newPage(pageLabel);
  }

  function paragraph(
    text: string,
    options: {
      x?: number;
      width?: number;
      size?: number;
      color?: readonly [number, number, number];
      font?: "helvetica" | "courier";
      style?: "normal" | "bold" | "italic";
      lineHeight?: number;
      pageLabel?: string;
      after?: number;
    } = {},
  ) {
    const x = options.x ?? M;
    const width = options.width ?? CONTENT_W;
    const size = options.size ?? 9;
    const lh = options.lineHeight ?? size * 0.52;
    doc.setFont(options.font ?? "helvetica", options.style ?? "normal");
    doc.setFontSize(size);
    ink(doc, options.color ?? C.ink);
    const lines = doc.splitTextToSize(clean(text), width) as string[];
    for (const line of lines) {
      ensure(lh + 1, options.pageLabel ?? currentLabel);
      doc.setFont(options.font ?? "helvetica", options.style ?? "normal");
      doc.setFontSize(size);
      ink(doc, options.color ?? C.ink);
      doc.text(line, x, y);
      y += lh;
    }
    y += options.after ?? 0;
  }

  function section(number: string, title: string, pageLabel = currentLabel) {
    ensure(17, pageLabel);
    y += 2;
    fill(doc, C.ink);
    doc.rect(M, y - 2.8, 6.5, 6.5, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(6.7);
    doc.setTextColor(248, 243, 255);
    doc.text(number, M + 1.35, y + 1.7);
    label(doc, title, M + 10, y + 2.6, C.ink, 9.5);
    stroke(doc, C.line);
    doc.setLineWidth(0.25);
    doc.line(M, y + 6, W - M, y + 6);
    y += 11;
  }

  function subsection(title: string, pageLabel = currentLabel) {
    ensure(12, pageLabel);
    y += 1;
    label(doc, title, M, y + 1.8, C.ink, 7.2);
    stroke(doc, C.line);
    doc.setLineWidth(0.2);
    doc.line(M, y + 4.5, W - M, y + 4.5);
    y += 9;
  }

  function callout(title: string, body: string, tone: "gold" | "critical" | "good" = "gold") {
    const border = tone === "gold" ? C.gold : tone === "critical" ? C.critical : C.good;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    const bodyLines = doc.splitTextToSize(clean(body), CONTENT_W - 14) as string[];
    const height = 12 + bodyLines.length * 4.2;
    ensure(height + 4);
    fill(doc, [245, 248, 252]);
    stroke(doc, border);
    doc.setLineWidth(0.3);
    doc.roundedRect(M, y, CONTENT_W, height, 1.5, 1.5, "FD");
    fill(doc, border);
    doc.rect(M, y, 1.1, height, "F");
    label(doc, title, M + 6, y + 5.5, C.ink, 7);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    ink(doc, C.muted);
    let by = y + 10;
    for (const line of bodyLines) {
      doc.text(line, M + 6, by);
      by += 4.2;
    }
    y += height + 5;
  }

  function metadataGrid(rows: [string, string][], columns = 2) {
    const colWidth = CONTENT_W / columns;
    rows.forEach(([key, value], index) => {
      const col = index % columns;
      const row = Math.floor(index / columns);
      if (col === 0) ensure(12);
      const baseY = y + row * 12;
      label(doc, key, M + col * colWidth, baseY, C.muted, 6.2);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.3);
      ink(doc, C.ink);
      doc.text(clean(value), M + col * colWidth, baseY + 4.6, { maxWidth: colWidth - 8 });
    });
    y += Math.ceil(rows.length / columns) * 12;
  }

  function codeBox(text: string, title: string, maxLines = 18) {
    doc.setFont("courier", "normal");
    doc.setFontSize(7);
    const lines = text.split("\n");
    const shown = lines.slice(0, maxLines);
    const width = CONTENT_W - 10;
    const wrapped: string[] = [];
    for (const line of shown) {
      const parts = doc.splitTextToSize(clean(line || " "), width) as string[];
      wrapped.push(...parts.slice(0, 2));
    }
    const boxHeight = Math.min(78, 10 + wrapped.length * 3.5 + (lines.length > maxLines ? 5 : 0));
    ensure(boxHeight + 5);
    fill(doc, C.code);
    stroke(doc, C.line);
    doc.setLineWidth(0.25);
    doc.roundedRect(M, y, CONTENT_W, boxHeight, 1.5, 1.5, "FD");
    label(doc, title, M + 4, y + 5, C.royal, 6.2);
    doc.setFont("courier", "normal");
    doc.setFontSize(7);
    ink(doc, C.ink);
    let ly = y + 10;
    for (const line of wrapped) {
      if (ly > y + boxHeight - 3) break;
      doc.text(line, M + 4, ly);
      ly += 3.5;
    }
    if (lines.length > maxLines) {
      doc.setFont("helvetica", "italic");
      doc.setFontSize(6.5);
      ink(doc, C.muted);
      doc.text("Capture truncated for this report.", M + 4, y + boxHeight - 3);
    }
    y += boxHeight + 4;
  }

  return {
    get y() {
      return y;
    },
    set y(value: number) {
      y = value;
    },
    newPage,
    ensure,
    paragraph,
    section,
    subsection,
    callout,
    metadataGrid,
    codeBox,
    header,
  };
}

function findingsIndex(doc: jsPDF, findings: Finding[], writer: ReturnType<typeof createWriter>) {
  writer.newPage("Findings index");
  writer.section("02", "Findings index", "Findings index");
  writer.paragraph(
    `${findings.length} finding${findings.length === 1 ? "" : "s"} included, ordered by severity and then confidence. Open the application for the full interactive evidence record.`,
    { size: 8.6, color: C.muted, after: 5, pageLabel: "Findings index" },
  );

  // Header bar.
  fill(doc, C.ink);
  doc.rect(M, writer.y, CONTENT_W, 7.5, "F");
  const cols = [
    { x: M + 2, w: 18, text: "ID" },
    { x: M + 20, w: 22, text: "SEVERITY" },
    { x: M + 42, w: 88, text: "FINDING" },
    { x: M + 130, w: 22, text: "CONF." },
    { x: M + 152, w: 22, text: "STATUS" },
  ];
  doc.setFont("helvetica", "bold");
  doc.setFontSize(5.8);
  doc.setTextColor(248, 243, 255);
  cols.forEach((col) => doc.text(col.text, col.x, writer.y + 4.8));
  writer.y += 7.5;

  findings.forEach((finding, index) => {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.2);
    const titleLines = doc.splitTextToSize(clean(finding.title), cols[2].w - 2) as string[];
    const rowHeight = Math.max(9, 4 + titleLines.length * 3.6);
    writer.ensure(rowHeight, "Findings index");
    if (index % 2 === 0) {
      fill(doc, [239, 244, 250]);
      doc.rect(M, writer.y, CONTENT_W, rowHeight, "F");
    }
    stroke(doc, C.line);
    doc.setLineWidth(0.15);
    doc.line(M, writer.y + rowHeight, W - M, writer.y + rowHeight);

    doc.setFont("courier", "normal");
    doc.setFontSize(6.3);
    ink(doc, C.muted);
    doc.text(finding.id, cols[0].x, writer.y + 5);

    fill(doc, severityColor[finding.severity]);
    doc.circle(cols[1].x + 1, writer.y + 4.2, 0.8, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(6.2);
    ink(doc, severityColor[finding.severity]);
    doc.text(finding.severity.toUpperCase(), cols[1].x + 3.3, writer.y + 5);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.2);
    ink(doc, C.ink);
    titleLines.forEach((line, lineIndex) => {
      doc.text(line, cols[2].x, writer.y + 4.5 + lineIndex * 3.6);
    });
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.2);
    ink(doc, C.muted);
    doc.text(clean(finding.categoryLabel), cols[2].x, writer.y + 4.5 + titleLines.length * 3.6);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.5);
    ink(doc, C.ink);
    doc.text(finding.confidence, cols[3].x, writer.y + 5);
    doc.text(finding.status.replace("-", " "), cols[4].x, writer.y + 5);

    writer.y += rowHeight;
  });

  writer.y += 7;
  writer.paragraph(
    "Severity and confidence are separate judgements. Severity reflects potential impact; confidence reflects the strength of the recorded observation.",
    { size: 7.5, color: C.muted, style: "italic", pageLabel: "Findings index" },
  );
}

function findingPage(doc: jsPDF, finding: Finding, writer: ReturnType<typeof createWriter>) {
  const pageLabel = `Finding ${finding.id}`;
  writer.newPage(pageLabel);
  fill(doc, severityColor[finding.severity]);
  doc.rect(0, 0, W, 3.2, "F");

  label(doc, finding.id, M, 27, C.muted, 7);
  label(doc, finding.categoryLabel, M + 25, 27, C.muted, 7);
  label(doc, `Severity: ${finding.severity}`, W - M, 27, severityColor[finding.severity], 7, "right");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(17);
  ink(doc, C.ink);
  const titleLines = doc.splitTextToSize(clean(finding.title), CONTENT_W) as string[];
  titleLines.forEach((line, index) => doc.text(line, M, 37 + index * 7.4));
  writer.y = 37 + titleLines.length * 7.4 + 3;

  writer.paragraph(clean(finding.summary), { size: 8.8, color: C.muted, after: 4, pageLabel });
  writer.metadataGrid(
    [
      ["TARGET PATH", finding.targetPath],
      ["DETECTED", dateLabel(finding.detectedAt)],
      ["STATUS", finding.status.replace("-", " ")],
      ["CONFIDENCE", finding.confidence],
    ],
    2,
  );
  writer.y += 1;

  writer.section("01", "Observed evidence", pageLabel);
  writer.codeBox(finding.evidence.response, "Observed response", 22);
  if (finding.evidence.note) {
    writer.paragraph(finding.evidence.note, {
      size: 7.4,
      color: C.muted,
      style: "italic",
      pageLabel,
      after: 3,
    });
  }

  if (finding.evidence.comparison && finding.evidence.comparison.length > 0) {
    writer.ensure(10);
    label(doc, "Signal comparison", M, writer.y, C.muted, 6.2);
    writer.y += 4;
    finding.evidence.comparison.slice(0, 5).forEach((row) => {
      writer.ensure(7);
      const verdictColor =
        row.verdict === "fail"
          ? C.critical
          : row.verdict === "warn"
            ? C.medium
            : row.verdict === "pass"
              ? C.good
              : C.muted;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(7.4);
      ink(doc, C.ink);
      doc.text(clean(row.signal), M, writer.y);
      doc.setFont("courier", "normal");
      doc.setFontSize(6.7);
      ink(doc, C.muted);
      doc.text(clean(row.baseline), M + 52, writer.y);
      ink(doc, C.ink);
      doc.text(clean(row.observed), M + 105, writer.y);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(6.2);
      ink(doc, verdictColor);
      doc.text(row.verdict.toUpperCase(), W - M, writer.y, { align: "right" });
      stroke(doc, C.line);
      doc.setLineWidth(0.12);
      doc.line(M, writer.y + 2, W - M, writer.y + 2);
      writer.y += 6;
    });
    writer.y += 4;
  }

  writer.section("02", "Interpretation", pageLabel);
  writer.paragraph("Impact", { size: 7.4, color: C.muted, font: "helvetica", style: "bold", pageLabel, after: 1 });
  writer.paragraph(finding.impact, { size: 8.3, color: C.ink, pageLabel, after: 4 });

  writer.ensure(30, pageLabel);
  const half = (CONTENT_W - 5) / 2;
  const boxTop = writer.y;
  const rationaleBox = (
    x: number,
    title: string,
    body: string,
    tone: readonly [number, number, number],
  ) => {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.4);
    const lines = doc.splitTextToSize(clean(body), half - 8) as string[];
    const boxHeight = 12 + lines.length * 3.8;
    fill(doc, [248, 251, 254]);
    stroke(doc, C.line);
    doc.setLineWidth(0.2);
    doc.roundedRect(x, boxTop, half, boxHeight, 1.2, 1.2, "FD");
    fill(doc, tone);
    doc.rect(x, boxTop, 1, boxHeight, "F");
    label(doc, title, x + 4, boxTop + 5, tone, 6.2);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.4);
    ink(doc, C.ink);
    let by = boxTop + 10;
    for (const line of lines) {
      doc.text(line, x + 4, by);
      by += 3.8;
    }
    return boxHeight;
  };

  const sevHeight = rationaleBox(
    M,
    `Severity rationale / ${finding.severity}`,
    finding.severityRationale,
    severityColor[finding.severity],
  );
  const confHeight = rationaleBox(
    M + half + 5,
    `Confidence rationale / ${finding.confidence}`,
    finding.confidenceRationale,
    C.royal,
  );
  writer.y += Math.max(sevHeight, confHeight) + 6;

  writer.section("03", "Remediation", pageLabel);
  finding.remediation.slice(0, 6).forEach((step, index) => {
    writer.ensure(9, pageLabel);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(6.5);
    ink(doc, C.royal);
    doc.text(String(index + 1).padStart(2, "0"), M, writer.y);
    writer.paragraph(step, { x: M + 8, width: CONTENT_W - 8, size: 8, color: C.ink, pageLabel, after: 2.5 });
  });

  if (finding.fixSnippet) {
    writer.codeBox(finding.fixSnippet, `Suggested fix / ${finding.fixLanguage ?? "config"}`, 12);
  }

  writer.section("04", "Verification", pageLabel);
  const v = finding.verification;
  const stateLabel =
    v.status === "verified-resolved"
      ? "VERIFIED RESOLVED"
      : v.status === "verified-open"
        ? "STILL PRESENT"
        : "NOT YET VERIFIED";
  label(doc, stateLabel, M, writer.y, v.status === "verified-resolved" ? C.good : C.medium, 7);
  writer.y += 4;
  if (v.note) {
    writer.paragraph(v.note, { size: 7.8, color: C.muted, pageLabel, after: 4 });
  }

  const beforeLines = Math.min(5, v.before.split("\n").length);
  const afterLines = v.after ? Math.min(5, v.after.split("\n").length) : 1;
  const boxHeight = 8 + Math.max(beforeLines, afterLines) * 3.4 + 3;
  writer.ensure(boxHeight + 4, pageLabel);
  const halfBox = (CONTENT_W - 4) / 2;
  const drawVerification = (
    x: number,
    title: string,
    text: string,
    tone: readonly [number, number, number],
    present: boolean,
  ) => {
    fill(doc, present ? [241, 249, 246] : [246, 249, 252]);
    stroke(doc, tone);
    doc.setLineWidth(0.2);
    doc.roundedRect(x, writer.y, halfBox, boxHeight, 1.2, 1.2, "FD");
    label(doc, title, x + 4, writer.y + 5, tone, 6);
    if (!present) {
      doc.setFont("helvetica", "italic");
      doc.setFontSize(7.3);
      ink(doc, C.muted);
      doc.text("No verification observation recorded.", x + 4, writer.y + 12);
      return;
    }
    doc.setFont("courier", "normal");
    doc.setFontSize(6.4);
    ink(doc, C.ink);
    text
      .split("\n")
      .slice(0, 5)
      .forEach((line, index) => {
        doc.text(clean(line), x + 4, writer.y + 10 + index * 3.4);
      });
  };
  drawVerification(M, "BEFORE", v.before, C.critical, true);
  drawVerification(M + halfBox + 4, "AFTER", v.after ?? "", C.good, Boolean(v.after));
  writer.y += boxHeight + 6;
}

function verificationPage(doc: jsPDF, scan: Scan, writer: ReturnType<typeof createWriter>) {
  if (!scan.verification) return;
  const pageLabel = "Verification result";
  writer.newPage(pageLabel);
  writer.section("02", "Verification result", pageLabel);
  const outcomeResolved = scan.verification.outcome === "resolved";
  label(
    doc,
    outcomeResolved ? "OBSERVED ISSUE RESOLVED" : "STILL PRESENT AFTER RESCAN",
    M,
    writer.y,
    outcomeResolved ? C.good : C.medium,
    8,
  );
  writer.y += 6;
  writer.paragraph(scan.verification.findingTitle, {
    size: 15,
    font: "helvetica",
    style: "bold",
    color: C.ink,
    pageLabel,
    after: 4,
  });
  writer.paragraph(scan.verification.note, { size: 9, color: C.muted, pageLabel, after: 6 });

  writer.codeBox(scan.verification.before, "Before / original observation", 14);
  writer.codeBox(scan.verification.after, "After / verification observation", 14);

  writer.callout(
    "Scope note",
    "A resolved verification marker means the specific recorded observation changed. It does not prove that the entire application is secure. Findings marked still present require remediation and another verification pass.",
    outcomeResolved ? "good" : "gold",
  );
}

export interface ReportResult {
  doc: jsPDF;
  pageCount: number;
  filename: string;
}

export function buildScanReport(scan: Scan, findings: Finding[], generatedAt = new Date()): ReportResult {
  const isSample = scan.dataSource === "sample";
  const doc = new jsPDF({ unit: "mm", format: "a4", compress: true });
  doc.setProperties({
    title: `BUG HUNTER LAB - ${scan.label} security evidence report`,
    subject: `Evidence-first security review of ${hostname(scan.target)}${isSample ? " (sample data)" : ""}`,
    author: "BUG HUNTER LAB / RAVENX 2026",
    keywords: "security report, evidence, RAVENX 2026",
    creator: "BUG HUNTER LAB",
  });

  coverPage(doc, scan, findings, generatedAt);

  const writer = createWriter(doc, "Executive summary");
  writer.newPage("Executive summary");
  writer.section("01", "Executive summary", "Executive summary");

  const counts = countBySeverity(findings);
  const open = findings.filter((finding) => finding.status === "open").length;
  const pending = findings.filter((finding) => finding.status === "pending").length;
  const resolved = findings.filter((finding) => finding.status === "resolved").length;

  const lead =
    findings.length === 0
      ? "This run produced no findings in the selected modules. A clean result is not proof that the application is secure."
      : `This review recorded ${findings.length} finding${findings.length === 1 ? "" : "s"} across ${scan.checks.length} selected module${scan.checks.length === 1 ? "" : "s"}. Every finding carries the observation that produced it, a separate risk interpretation and a verification path.`;
  writer.paragraph(lead, { size: 10, color: C.ink, lineHeight: 5.2, pageLabel: "Executive summary", after: 7 });

  // Severity boxes.
  const boxW = (CONTENT_W - 9) / 4;
  const countsEntries: [Severity, number][] = [
    ["critical", counts.critical],
    ["high", counts.high],
    ["medium", counts.medium],
    ["low", counts.low],
  ];
  countsEntries.forEach(([severity, count], index) => {
    const x = M + index * (boxW + 3);
    fill(doc, [246, 249, 252]);
    stroke(doc, C.line);
    doc.setLineWidth(0.25);
    doc.roundedRect(x, writer.y, boxW, 27, 1.3, 1.3, "FD");
    fill(doc, severityColor[severity]);
    doc.rect(x, writer.y, boxW, 1.2, "F");
    label(doc, severity, x + 4, writer.y + 7, severityColor[severity], 6.2);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(19);
    ink(doc, C.ink);
    doc.text(String(count), x + 4, writer.y + 18);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.4);
    ink(doc, C.muted);
    doc.text(count === 1 ? "finding" : "findings", x + 4, writer.y + 23);
  });
  writer.y += 34;

  writer.paragraph(
    `Status: ${open} open, ${pending} pending verification, ${resolved} resolved. Severity reflects potential impact; confidence reflects evidence strength.`,
    { size: 8, color: C.muted, pageLabel: "Executive summary", after: 6 },
  );

  writer.subsection("Scan details", "Executive summary");
  writer.metadataGrid(
    [
      ["TARGET", scan.target],
      ["SCAN", `${scan.label} / ${scan.id}`],
      ["STARTED", dateLabel(scan.startedAt)],
      ["COMPLETED", scan.completedAt ? dateLabel(scan.completedAt) : "Not completed"],
      ["CHECKS", scan.checks.join(", ")],
      ["DATA SOURCE", isSample ? "Sample data" : "Live SQLite scan record"],
    ],
    2,
  );

  writer.subsection("Coverage", "Executive summary");
  const categoryCounts = (["headers", "cookies", "paths", "injection"] as const).map((category) => ({
    category,
    count: findings.filter((finding) => finding.category === category).length,
    checked: scan.checks.includes(category),
  }));
  const coverageRows = [
    ["HTTP Header Inspector", "CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy", categoryCounts[0]],
    ["Cookie Security Analyzer", "Secure, HttpOnly, SameSite", categoryCounts[1]],
    ["Exposed Path Detector", "Allowlisted paths with baseline comparison", categoryCounts[2]],
    ["Injection Vulnerability Tester", "Low-impact probes with baseline comparison", categoryCounts[3]],
  ] as const;
  coverageRows.forEach(([title, description, coverage]) => {
    writer.ensure(10, "Executive summary");
    fill(doc, coverage.checked ? C.good : C.muted);
    doc.circle(M + 1.2, writer.y - 1.3, 0.8, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.8);
    ink(doc, C.ink);
    doc.text(title, M + 5, writer.y);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.8);
    ink(doc, C.muted);
    doc.text(description, M + 62, writer.y);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    ink(doc, coverage.checked ? C.ink : C.muted);
    doc.text(
      coverage.checked ? `${coverage.count} finding${coverage.count === 1 ? "" : "s"}` : "not selected",
      W - M,
      writer.y,
      { align: "right" },
    );
    writer.y += 8;
  });
  writer.y += 3;

  writer.callout(
    isSample ? "Sample data disclaimer" : "Scope & limitations",
    isSample
      ? "This document is marked as illustrative sample data."
      : "This document was generated from real SQLite-persisted scan records. Non-destructive scoped checks only; an absence of findings is not proof that the application is completely secure.",
    isSample ? "gold" : "good",
  );

  if (findings.length > 0) {
    findingsIndex(doc, findings, writer);
    findings.forEach((finding) => findingPage(doc, finding, writer));
  }
  if (scan.verification) {
    verificationPage(doc, scan, writer);
  }

  const total = doc.getNumberOfPages();
  for (let page = 2; page <= total; page += 1) {
    doc.setPage(page);
    stroke(doc, C.line);
    doc.setLineWidth(0.25);
    doc.line(M, H - 15, W - M, H - 15);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(6.2);
    ink(doc, C.muted);
    doc.text(
      isSample ? "BUG HUNTER LAB - evidence-first review - sample data" : "BUG HUNTER LAB - evidence-first review",
      M,
      H - 9.5,
    );
    doc.text(`Page ${page} of ${total}`, W - M, H - 9.5, { align: "right" });
  }

  const safeHost = hostname(scan.target).replace(/[^a-z0-9.-]+/gi, "-");
  const safeId = scan.id.replace(/[^a-z0-9-]+/gi, "-");
  return {
    doc,
    pageCount: total,
    filename: `BugHunterLab_${safeHost}_${safeId}_report.pdf`,
  };
}

export function downloadScanReport(scan: Scan, findings: Finding[]): ReportResult {
  const result = buildScanReport(scan, findings);
  result.doc.save(result.filename);
  return result;
}
