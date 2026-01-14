import jsPDF from 'jspdf';
import 'jspdf-autotable';

/**
 * COMPREHENSIVE PDF GENERATOR - RETRO BLOCK THEME
 * Complete data export from ALL tabs on Scan Results page
 * Tabs: Mission Brief, Recon Report, Threat Catalog, Attack Matrix, Defense Playbook, Intel Analysis
 */

// RETRO BLOCK THEME COLORS
const COLORS = {
  black: [0, 0, 0],
  white: [255, 247, 223],      // #fff7df
  primary: [18, 20, 23],       // #121417
  accent: [241, 86, 63],       // #f1563f
  coral: [255, 107, 107],      // #FF6B6B
  pink: [255, 105, 180],       // #FF69B4
  yellow: [255, 217, 61],      // #FFD93D
  cyan: [94, 198, 232],        // #5ec6e8
  green: [76, 175, 145],       // #4CAF91
  purple: [155, 89, 182],      // #9b59b6
  blue: [65, 105, 225],        // #4169E1
  darkBg: [26, 29, 35],
  gray: [128, 128, 128],
  lightGray: [200, 200, 200]
};

// VT323 font style for retro look
const FONTS = {
  heading: 'helvetica',  // VT323 not available, use helvetica bold
  body: 'helvetica'
};

/**
 * Create Link&Load logo as SVG data URI (Retro Block Style)
 */
const createLogoDataURI = () => {
  const svg = `
    <svg width="160" height="50" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <style>
          .logo-text { 
            font-family: 'Courier New', monospace; 
            font-size: 28px; 
            font-weight: 700;
            fill: #000;
          }
          .logo-amp {
            font-size: 24px;
            fill: #f1563f;
            font-weight: 700;
          }
        </style>
      </defs>
      <rect x="2" y="2" width="156" height="46" fill="#fff7df" stroke="#000" stroke-width="4"/>
      <text x="18" y="34" class="logo-text">Link</text>
      <text x="73" y="32" class="logo-amp">&amp;</text>
      <text x="95" y="34" class="logo-text">Load</text>
    </svg>
  `;
  return `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}`;
};

/**
 * RETRO BLOCK PDF BUILDER CLASS
 */
class RetroBlockPDFBuilder {
  constructor(title, subtitle) {
    this.pdf = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
      compress: true
    });

    this.pageWidth = this.pdf.internal.pageSize.getWidth();
    this.pageHeight = this.pdf.internal.pageSize.getHeight();
    this.margin = 15;
    this.contentWidth = this.pageWidth - (2 * this.margin);
    this.yPos = 55;
    this.pageCount = 1;
    this.title = title;
    this.subtitle = subtitle;

    this.addRetroHeader();
  }

  /**
   * RETRO BLOCK HEADER with bold borders and geometric shapes
   */
  addRetroHeader() {
    const pdf = this.pdf;

    // Background with retro cream color
    pdf.setFillColor(...COLORS.white);
    pdf.rect(0, 0, this.pageWidth, 45, 'F');

    // Bold black border at bottom
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(3);
    pdf.line(0, 45, this.pageWidth, 45);

    // Decorative corner block (green)
    pdf.setFillColor(...COLORS.green);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(2);
    pdf.rect(this.pageWidth - 25, 5, 15, 15, 'FD');

    // Logo
    try {
      const logoData = createLogoDataURI();
      pdf.addImage(logoData, 'SVG', 15, 10, 54, 17);
    } catch (e) {
      pdf.setFontSize(18);
      pdf.setFont(FONTS.heading, 'bold');
      pdf.setTextColor(...COLORS.black);
      pdf.text('Link&Load', 15, 25);
    }

    // Title in retro block style
    pdf.setFontSize(16);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text(this.title.toUpperCase(), this.pageWidth - 15, 18, { align: 'right' });

    if (this.subtitle) {
      pdf.setFontSize(9);
      pdf.setFont(FONTS.body, 'normal');
      pdf.setTextColor(...COLORS.gray);
      const maxWidth = 80;
      const subtitleLines = pdf.splitTextToSize(this.subtitle, maxWidth);
      pdf.text(subtitleLines, this.pageWidth - 15, 26, { align: 'right' });
    }

    this.yPos = 55;
  }

  /**
   * RETRO FOOTER - "Locked on Link&Load" with logo
   */
  addRetroFooter() {
    const pdf = this.pdf;
    const footerY = this.pageHeight - 20;

    // Dark footer background
    pdf.setFillColor(...COLORS.darkBg);
    pdf.rect(0, footerY, this.pageWidth, 20, 'F');

    // Bold top border
    pdf.setDrawColor(...COLORS.accent);
    pdf.setLineWidth(2);
    pdf.line(0, footerY, this.pageWidth, footerY);

    // "Locked on Link&Load" text
    pdf.setFontSize(12);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.white);
    pdf.text('LOCKED ON LINK&LOAD', this.pageWidth / 2, footerY + 12, { align: 'center' });

    // Page number
    pdf.setFontSize(9);
    pdf.setFont(FONTS.body, 'normal');
    pdf.text(`Page ${this.pageCount}`, this.pageWidth - 15, footerY + 12, { align: 'right' });
  }

  /**
   * Check if new page needed
   */
  checkAddPage() {
    if (this.yPos > this.pageHeight - 35) {
      this.addRetroFooter();
      this.pdf.addPage();
      this.pageCount++;
      this.addRetroHeader();
      return true;
    }
    return false;
  }

  /**
   * RETRO BLOCK SECTION TITLE - Bold colored block with black border
   */
  addRetroSectionTitle(title, colorRGB = COLORS.accent) {
    this.checkAddPage();
    this.yPos += 8;

    const pdf = this.pdf;
    const blockHeight = 12;

    // Colored block with black border
    pdf.setFillColor(...colorRGB);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(3);
    pdf.rect(this.margin, this.yPos - 8, this.contentWidth, blockHeight, 'FD');

    // White text on colored block
    pdf.setFontSize(14);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(255, 255, 255);
    pdf.text(title.toUpperCase(), this.margin + 5, this.yPos + 1);

    this.yPos += blockHeight + 5;
  }

  /**
   * RETRO BLOCK - Data card with border and optional colored background
   */
  addRetroBlock(label, value, colorRGB = COLORS.white, options = {}) {
    const {
      width = 45,
      height = 20,
      valueSize = 16,
      labelSize = 8,
      bold = true
    } = options;

    this.checkAddPage();

    const pdf = this.pdf;
    const x = this.margin;
    const y = this.yPos;

    // Block with retro border
    pdf.setFillColor(...colorRGB);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(2);
    pdf.rect(x, y, width, height, 'FD');

    // Drop shadow effect
    pdf.setFillColor(0, 0, 0, 0.15);
    pdf.rect(x + 2, y + 2, width, height, 'F');
    pdf.setFillColor(...colorRGB);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(2);
    pdf.rect(x, y, width, height, 'FD');

    // Label
    pdf.setFontSize(labelSize);
    pdf.setFont(FONTS.body, 'normal');
    pdf.setTextColor(...COLORS.black);
    const labelLines = pdf.splitTextToSize(label.toUpperCase(), width - 6);
    pdf.text(labelLines, x + width / 2, y + 6, { align: 'center' });

    // Value
    pdf.setFontSize(valueSize);
    pdf.setFont(FONTS.heading, bold ? 'bold' : 'normal');
    pdf.setTextColor(...COLORS.black);
    pdf.text(String(value), x + width / 2, y + height - 4, { align: 'center' });

    return { width, height };
  }

  /**
   * Add multiple retro blocks in a row
   */
  addRetroBlockRow(blocks, gap = 5) {
    this.checkAddPage();

    const startY = this.yPos;
    let xOffset = this.margin;
    let maxHeight = 0;

    blocks.forEach((block) => {
      const pdf = this.pdf;
      const { label, value, color = COLORS.cyan, width = 45, height = 20 } = block;

      // Draw block
      pdf.setFillColor(...color);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(2);

      // Shadow
      pdf.setFillColor(0, 0, 0, 0.15);
      pdf.rect(xOffset + 2, startY + 2, width, height, 'F');

      // Main block
      pdf.setFillColor(...color);
      pdf.rect(xOffset, startY, width, height, 'FD');

      // Label
      pdf.setFontSize(7);
      pdf.setFont(FONTS.body, 'normal');
      pdf.setTextColor(...COLORS.black);
      pdf.text(label.toUpperCase(), xOffset + width / 2, startY + 5, { align: 'center' });

      // Value
      pdf.setFontSize(14);
      pdf.setFont(FONTS.heading, 'bold');
      pdf.text(String(value), xOffset + width / 2, startY + height - 4, { align: 'center' });

      xOffset += width + gap;
      maxHeight = Math.max(maxHeight, height);
    });

    this.yPos += maxHeight + 8;
  }

  /**
   * Add text with retro styling
   */
  addRetroText(text, options = {}) {
    const {
      fontSize = 10,
      bold = false,
      color = COLORS.black,
      indent = 0,
      lineHeight = 5,
      uppercase = false
    } = options;

    const pdf = this.pdf;
    pdf.setFontSize(fontSize);
    pdf.setFont(FONTS.body, bold ? 'bold' : 'normal');
    pdf.setTextColor(...color);

    const displayText = uppercase ? text.toUpperCase() : text;
    const lines = pdf.splitTextToSize(displayText, this.contentWidth - indent);

    for (const line of lines) {
      this.checkAddPage();
      pdf.text(line, this.margin + indent, this.yPos);
      this.yPos += lineHeight;
    }

    this.yPos += 2;
  }

  /**
   * Add key-value pair
   */
  addKeyValue(key, value, options = {}) {
    const { bold = false, keyColor = COLORS.gray, valueColor = COLORS.black } = options;

    this.checkAddPage();

    const pdf = this.pdf;
    pdf.setFontSize(10);
    pdf.setFont(FONTS.body, 'normal');
    pdf.setTextColor(...keyColor);
    pdf.text(key.toUpperCase() + ':', this.margin, this.yPos);

    pdf.setFont(FONTS.body, bold ? 'bold' : 'normal');
    pdf.setTextColor(...valueColor);
    const valueText = String(value);
    const maxWidth = this.contentWidth - 55;
    const valueLines = pdf.splitTextToSize(valueText, maxWidth);
    pdf.text(valueLines, this.margin + 52, this.yPos);

    this.yPos += Math.max(6, valueLines.length * 5);
  }

  /**
   * Add retro-styled table
   */
  addRetroTable(headers, rows, options = {}) {
    const {
      headerColor = COLORS.purple,
      alternateRowColors = true
    } = options;

    this.checkAddPage();

    this.pdf.autoTable({
      head: [headers],
      body: rows,
      startY: this.yPos,
      margin: { left: this.margin, right: this.margin },
      styles: {
        fontSize: 9,
        font: FONTS.body,
        cellPadding: 4,
        textColor: COLORS.black,
        lineColor: COLORS.black,
        lineWidth: 1.5
      },
      headStyles: {
        fillColor: headerColor,
        textColor: [255, 255, 255],
        fontStyle: 'bold',
        halign: 'left',
        lineWidth: 2
      },
      alternateRowStyles: alternateRowColors ? {
        fillColor: COLORS.white
      } : {},
      didDrawPage: (data) => {
        this.yPos = data.cursor.y + 6;
      }
    });
  }

  /**
   * Add retro bullet list
   */
  addRetroBulletList(items, options = {}) {
    const { color = COLORS.black, bulletColor = COLORS.accent } = options;

    this.pdf.setFontSize(10);
    this.pdf.setFont(FONTS.body, 'normal');
    this.pdf.setTextColor(...color);

    for (const item of items) {
      this.checkAddPage();

      // Retro block bullet
      this.pdf.setFillColor(...bulletColor);
      this.pdf.setDrawColor(...COLORS.black);
      this.pdf.setLineWidth(1);
      this.pdf.rect(this.margin + 2, this.yPos - 3, 3, 3, 'FD');

      // Text
      const lines = this.pdf.splitTextToSize(item, this.contentWidth - 12);
      for (const line of lines) {
        this.checkAddPage();
        this.pdf.text(line, this.margin + 10, this.yPos);
        this.yPos += 5;
      }

      this.yPos += 2;
    }
  }

  /**
   * Add horizontal bar chart (retro style)
   */
  addRetroBarChart(data, options = {}) {
    const { title = '', maxValue = null } = options;

    if (title) {
      this.addRetroText(title, { bold: true, fontSize: 11 });
      this.yPos += 3;
    }

    const max = maxValue || Math.max(...data.map(d => d.value));
    const barHeight = 8;
    const barSpacing = 3;

    data.forEach(item => {
      this.checkAddPage();

      const pdf = this.pdf;
      const barWidth = (item.value / max) * (this.contentWidth - 60);

      // Label
      pdf.setFontSize(9);
      pdf.setFont(FONTS.body, 'bold');
      pdf.setTextColor(...COLORS.black);
      pdf.text(item.label, this.margin, this.yPos + 5);

      // Bar with border
      pdf.setFillColor(...(item.color || COLORS.cyan));
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(1.5);
      pdf.rect(this.margin + 35, this.yPos, barWidth, barHeight, 'FD');

      // Value
      pdf.setFontSize(8);
      pdf.text(String(item.value), this.margin + 35 + barWidth + 3, this.yPos + 5);

      this.yPos += barHeight + barSpacing;
    });

    this.yPos += 5;
  }

  /**
   * Add spacer
   */
  addSpacer(height = 5) {
    this.yPos += height;
  }

  /**
   * Finalize PDF with all footers
   */
  finalize() {
    this.addRetroFooter();

    const totalPages = this.pdf.internal.pages.length - 1;
    for (let i = 1; i <= totalPages; i++) {
      this.pdf.setPage(i);

      const footerY = this.pageHeight - 20;
      this.pdf.setFontSize(9);
      this.pdf.setFont(FONTS.body, 'normal');
      this.pdf.setTextColor(...COLORS.white);
      this.pdf.text(`Page ${i} of ${totalPages}`, this.pageWidth - 15, footerY + 12, { align: 'right' });
    }

    return this.pdf;
  }
}

/**
 * Helper: Get severity color (retro palette)
 */
const getSeverityColor = (severity) => {
  const sev = (severity || 'info').toLowerCase();
  switch (sev) {
    case 'critical': return COLORS.coral;
    case 'high': return COLORS.accent;
    case 'medium': return COLORS.yellow;
    case 'low': return COLORS.cyan;
    default: return COLORS.gray;
  }
};

/**
 * Helper: Get risk color
 */
const getRiskColor = (level) => {
  const lvl = (level || 'low').toLowerCase();
  switch (lvl) {
    case 'critical': return COLORS.coral;
    case 'high': return COLORS.accent;
    case 'medium': return COLORS.yellow;
    case 'low': return COLORS.green;
    default: return COLORS.gray;
  }
};

/**
 * MAIN COMPREHENSIVE PDF GENERATION FUNCTION
 * Extracts data from ALL tabs and creates complete report
 */
export const generateScanResultsPDF = async (scanId, targetUrl, scanData) => {
  try {
    console.log('[PDF] Generating comprehensive retro-block PDF...', { scanId, targetUrl, scanData });

    // Initialize PDF Builder
    const subtitle = targetUrl || `Scan ID: ${scanId}`;
    const builder = new RetroBlockPDFBuilder('SECURITY SCAN REPORT', subtitle);

    // Extract data from DOM and scanData
    const extractedData = extractAllScanData(scanData);

    // ============================================
    // TAB 1: MISSION BRIEF (Executive Summary)
    // ============================================
    builder.addRetroSectionTitle('01. MISSION BRIEF', COLORS.accent);

    // Scan Information
    builder.addRetroText('SCAN INFORMATION', { bold: true, fontSize: 11, uppercase: true });
    builder.addSpacer(3);
    builder.addKeyValue('Scan ID', scanId);
    builder.addKeyValue('Target URL', targetUrl || 'N/A');
    builder.addKeyValue('Scan Date', new Date().toLocaleDateString());
    builder.addKeyValue('Scan Time', new Date().toLocaleTimeString());
    if (scanData?.status) builder.addKeyValue('Status', scanData.status);

    builder.addSpacer(8);

    // Risk Assessment Block
    const riskLevel = extractedData.riskLevel || 'Unknown';
    const riskScore = extractedData.riskScore || 0;
    const riskColor = getRiskColor(riskLevel);

    builder.addRetroText('RISK ASSESSMENT', { bold: true, fontSize: 11, uppercase: true });
    builder.addSpacer(3);

    builder.addRetroBlockRow([
      { label: 'Risk Level', value: riskLevel, color: riskColor, width: 50, height: 22 },
      { label: 'Risk Score', value: `${riskScore}/10`, color: riskColor, width: 50, height: 22 }
    ]);

    // Vulnerability Statistics (Retro blocks)
    builder.addRetroText('THREAT OVERVIEW', { bold: true, fontSize: 11, uppercase: true });
    builder.addSpacer(3);

    const vulnStats = extractedData.vulnerabilityStats;
    builder.addRetroBlockRow([
      { label: 'Critical', value: vulnStats.critical, color: COLORS.coral, width: 36, height: 18 },
      { label: 'High', value: vulnStats.high, color: COLORS.accent, width: 36, height: 18 },
      { label: 'Medium', value: vulnStats.medium, color: COLORS.yellow, width: 36, height: 18 },
      { label: 'Low', value: vulnStats.low, color: COLORS.cyan, width: 36, height: 18 },
      { label: 'Info', value: vulnStats.info, color: COLORS.gray, width: 36, height: 18 }
    ], 3);

    builder.addRetroBlockRow([
      { label: 'Total Vulnerabilities', value: vulnStats.total, color: COLORS.purple, width: 90, height: 20 }
    ]);

    // Executive Summary Text
    if (extractedData.executiveSummary) {
      builder.addSpacer(8);
      builder.addRetroText('EXECUTIVE SUMMARY', { bold: true, fontSize: 11, uppercase: true });
      builder.addSpacer(3);
      builder.addRetroText(extractedData.executiveSummary, { lineHeight: 5.5 });
    }

    // ============================================
    // TAB 2: RECON REPORT (Overview & Technical Details)
    // ============================================
    builder.addSpacer(10);
    builder.addRetroSectionTitle('02. RECON REPORT', COLORS.cyan);

    // Technical Scan Details
    if (extractedData.scanDetails) {
      const details = extractedData.scanDetails;
      builder.addRetroText('TECHNICAL DETAILS', { bold: true, fontSize: 11, uppercase: true });
      builder.addSpacer(3);

      if (details.scanType) builder.addKeyValue('Scan Type', details.scanType);
      if (details.scanMode) builder.addKeyValue('Scan Mode', details.scanMode);
      if (details.duration) builder.addKeyValue('Duration', details.duration);
      if (details.requestsMade) builder.addKeyValue('Requests Made', details.requestsMade);
      if (details.pagesScanned) builder.addKeyValue('Pages Scanned', details.pagesScanned);
      if (details.scannerVersion) builder.addKeyValue('Scanner Version', details.scannerVersion);
    }

    // Technology Stack
    if (extractedData.technologies && extractedData.technologies.length > 0) {
      builder.addSpacer(8);
      builder.addRetroText('TECHNOLOGY STACK', { bold: true, fontSize: 11, uppercase: true });
      builder.addSpacer(3);
      builder.addRetroBulletList(extractedData.technologies, { bulletColor: COLORS.cyan });
    }

    // ============================================
    // TAB 3: THREAT CATALOG (All Vulnerabilities)
    // ============================================
    builder.addSpacer(10);
    builder.addRetroSectionTitle('03. THREAT CATALOG', COLORS.pink);

    const vulnerabilities = extractedData.vulnerabilities || [];

    if (vulnerabilities.length > 0) {
      // Severity Distribution Chart
      builder.addRetroText('SEVERITY DISTRIBUTION', { bold: true, fontSize: 11, uppercase: true });
      builder.addSpacer(3);

      const severityData = [
        { label: 'CRITICAL', value: vulnStats.critical, color: COLORS.coral },
        { label: 'HIGH', value: vulnStats.high, color: COLORS.accent },
        { label: 'MEDIUM', value: vulnStats.medium, color: COLORS.yellow },
        { label: 'LOW', value: vulnStats.low, color: COLORS.cyan }
      ].filter(d => d.value > 0);

      builder.addRetroBarChart(severityData);
      builder.addSpacer(8);

      // Detailed Vulnerability Listings (grouped by severity)
      ['critical', 'high', 'medium', 'low', 'info'].forEach(severity => {
        const vulnsOfSeverity = vulnerabilities.filter(v =>
          (v.severity || 'info').toLowerCase() === severity
        );

        if (vulnsOfSeverity.length > 0) {
          const severityColor = getSeverityColor(severity);
          builder.addRetroText(`${severity.toUpperCase()} SEVERITY (${vulnsOfSeverity.length})`, {
            bold: true,
            fontSize: 11,
            color: severityColor,
            uppercase: true
          });
          builder.addSpacer(3);

          vulnsOfSeverity.forEach((vuln, index) => {
            builder.checkAddPage();

            const pdf = builder.pdf;
            const startY = builder.yPos;

            // Vulnerability block with border
            pdf.setDrawColor(...COLORS.black);
            pdf.setLineWidth(2);

            // Title
            pdf.setFontSize(10);
            pdf.setFont(FONTS.heading, 'bold');
            pdf.setTextColor(...COLORS.black);
            pdf.text(`${index + 1}. ${vuln.title || vuln.name || 'Untitled Vulnerability'}`, builder.margin + 3, builder.yPos);
            builder.yPos += 6;

            // CVE/CWE
            if (vuln.cve || vuln.cwe) {
              pdf.setFontSize(8);
              pdf.setFont(FONTS.body, 'normal');
              pdf.setTextColor(...COLORS.gray);
              const ids = [vuln.cve, vuln.cwe].filter(Boolean).join(' | ');
              pdf.text(ids, builder.margin + 3, builder.yPos);
              builder.yPos += 5;
            }

            // Description
            if (vuln.description) {
              pdf.setFontSize(9);
              pdf.setFont(FONTS.body, 'normal');
              pdf.setTextColor(...COLORS.black);
              const descLines = pdf.splitTextToSize(vuln.description, builder.contentWidth - 8);
              descLines.forEach(line => {
                builder.checkAddPage();
                pdf.text(line, builder.margin + 3, builder.yPos);
                builder.yPos += 4.5;
              });
            }

            // URL
            if (vuln.url) {
              pdf.setFontSize(8);
              pdf.setFont(FONTS.body, 'italic');
              pdf.setTextColor(...COLORS.blue);
              pdf.text(`URL: ${vuln.url}`, builder.margin + 3, builder.yPos);
              builder.yPos += 5;
            }

            // Draw border around vulnerability
            const boxHeight = builder.yPos - startY + 2;
            pdf.setDrawColor(...severityColor);
            pdf.rect(builder.margin, startY - 4, builder.contentWidth, boxHeight, 'S');

            builder.yPos += 5;
          });

          builder.addSpacer(5);
        }
      });
    } else {
      builder.addRetroText('No vulnerabilities detected in this scan.', {
        bold: true,
        color: COLORS.green
      });
    }

    // ============================================
    // TAB 4: ATTACK MATRIX (MITRE ATT&CK)
    // ============================================
    builder.addSpacer(10);
    builder.addRetroSectionTitle('04. ATTACK MATRIX', COLORS.purple);

    const mitreTechniques = extractedData.mitreTechniques || [];

    if (mitreTechniques.length > 0) {
      builder.addRetroText(`Identified ${mitreTechniques.length} MITRE ATT&CK techniques related to detected vulnerabilities:`, {
        lineHeight: 5.5
      });
      builder.addSpacer(5);

      const mitreTableData = mitreTechniques.map(t => [
        t.technique_id || t.id || 'N/A',
        t.name || 'N/A',
        t.tactic || 'N/A',
        t.description ? t.description.substring(0, 60) + '...' : 'N/A'
      ]);

      builder.addRetroTable(
        ['Technique ID', 'Name', 'Tactic', 'Description'],
        mitreTableData,
        { headerColor: COLORS.purple }
      );
    } else {
      builder.addRetroText('No MITRE ATT&CK technique mappings available for this scan.', {
        color: COLORS.gray
      });
    }

    // ============================================
    // TAB 5: DEFENSE PLAYBOOK (Remediation)
    // ============================================
    builder.addSpacer(10);
    builder.addRetroSectionTitle('05. DEFENSE PLAYBOOK', COLORS.green);

    // Priority Actions
    builder.addRetroText('PRIORITY ACTIONS', { bold: true, fontSize: 11, uppercase: true });
    builder.addSpacer(3);

    const recommendations = [];
    if (vulnStats.critical > 0) {
      recommendations.push(`Address ${vulnStats.critical} critical severity vulnerabilities immediately - highest priority`);
    }
    if (vulnStats.high > 0) {
      recommendations.push(`Remediate ${vulnStats.high} high severity vulnerabilities within 48 hours`);
    }
    if (vulnStats.medium > 0) {
      recommendations.push(`Plan fixes for ${vulnStats.medium} medium severity issues within next sprint cycle`);
    }
    recommendations.push('Implement security patches and updates for all identified vulnerabilities');
    recommendations.push('Review and update security policies and access controls');
    recommendations.push('Conduct regular vulnerability assessments to identify new threats');
    recommendations.push('Monitor for emerging threats and attack patterns');
    recommendations.push('Train development teams on secure coding practices');
    recommendations.push('Implement Web Application Firewall (WAF) rules');
    recommendations.push('Enable security headers and Content Security Policy (CSP)');
    recommendations.push('Perform penetration testing to validate remediation');

    builder.addRetroBulletList(recommendations, { bulletColor: COLORS.green });

    // Remediation Timeline (if available)
    if (extractedData.remediationTimeline) {
      builder.addSpacer(8);
      builder.addRetroText('REMEDIATION TIMELINE', { bold: true, fontSize: 11, uppercase: true });
      builder.addSpacer(3);

      const timeline = extractedData.remediationTimeline;

      if (timeline.immediate) {
        builder.addRetroText('IMMEDIATE ACTION (0-48 hours)', { bold: true, fontSize: 10, color: COLORS.coral, uppercase: true });
        builder.addRetroBulletList(timeline.immediate.slice(0, 5), { bulletColor: COLORS.coral });
        builder.addSpacer(5);
      }

      if (timeline.shortTerm) {
        builder.addRetroText('SHORT TERM (1-7 days)', { bold: true, fontSize: 10, color: COLORS.yellow, uppercase: true });
        builder.addRetroBulletList(timeline.shortTerm.slice(0, 5), { bulletColor: COLORS.yellow });
        builder.addSpacer(5);
      }

      if (timeline.mediumTerm) {
        builder.addRetroText('MEDIUM TERM (1-4 weeks)', { bold: true, fontSize: 10, color: COLORS.cyan, uppercase: true });
        builder.addRetroBulletList(timeline.mediumTerm.slice(0, 5), { bulletColor: COLORS.cyan });
      }
    }

    // ============================================
    // TAB 6: INTEL ANALYSIS (AI Insights)
    // ============================================
    builder.addSpacer(10);
    builder.addRetroSectionTitle('06. INTEL ANALYSIS', COLORS.blue);

    const aiInsights = extractedData.aiInsights || [];

    if (aiInsights.length > 0) {
      builder.addRetroText(`Generated ${aiInsights.length} AI-powered security insights:`, { lineHeight: 5.5 });
      builder.addSpacer(5);

      aiInsights.forEach((insight, index) => {
        builder.checkAddPage();

        builder.addRetroText(`INSIGHT ${index + 1}`, { bold: true, fontSize: 10, color: COLORS.blue, uppercase: true });
        builder.addSpacer(2);

        if (insight.title) {
          builder.addRetroText(insight.title, { bold: true, fontSize: 10 });
        }

        if (insight.analysis) {
          builder.addRetroText(insight.analysis, { lineHeight: 5.5 });
        }

        if (insight.recommendation) {
          builder.addSpacer(3);
          builder.addRetroText('RECOMMENDATION:', { bold: true, fontSize: 9, color: COLORS.green, uppercase: true });
          builder.addRetroText(insight.recommendation, { lineHeight: 5.5 });
        }

        builder.addSpacer(5);
      });
    } else {
      builder.addRetroText('No AI insights available for this scan.', { color: COLORS.gray });
      builder.addSpacer(5);
      builder.addRetroText('AI analysis provides contextual insights about vulnerabilities, attack patterns, and recommended security measures.', {
        lineHeight: 5.5
      });
    }

    // ============================================
    // CONCLUSION
    // ============================================
    builder.addSpacer(10);
    builder.addRetroSectionTitle('CONCLUSION & NEXT STEPS', COLORS.accent);

    const conclusionText = vulnStats.total > 0
      ? `This security assessment has identified ${vulnStats.total} vulnerabilities requiring attention. ` +
      `Prioritize remediation based on severity: ${vulnStats.critical} critical and ${vulnStats.high} high-risk items demand immediate action. ` +
      'Regular security assessments and continuous monitoring are essential to maintain a strong security posture.'
      : 'This security assessment did not identify any significant vulnerabilities. However, regular security assessments ' +
      'and continuous monitoring are still recommended to maintain a strong security posture and detect emerging threats.';

    builder.addRetroText(conclusionText, { lineHeight: 6 });

    builder.addSpacer(8);
    builder.addRetroText('RECOMMENDED ACTIONS:', { bold: true, fontSize: 11, uppercase: true });
    builder.addSpacer(3);
    builder.addRetroBulletList([
      'Implement all security fixes based on priority',
      'Schedule follow-up assessment after remediation',
      'Establish continuous security monitoring',
      'Integrate security testing into CI/CD pipeline',
      'Document and track remediation efforts',
      'Conduct security training for teams'
    ], { bulletColor: COLORS.accent });

    // ============================================
    // FINALIZE PDF
    // ============================================
    const pdf = builder.finalize();

    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `LinkLoad_Security_Report_${scanId.substring(0, 8)}_${timestamp}.pdf`;

    pdf.save(filename);

    console.log('[PDF] Generated successfully:', filename);
    return { success: true, filename };

  } catch (error) {
    console.error('[PDF] Generation failed:', error);
    return { success: false, error: error.message };
  }
};

/**
 * EXTRACT ALL SCAN DATA FROM DOM AND API
 */
function extractAllScanData(scanData) {
  const data = {
    vulnerabilities: [],
    vulnerabilityStats: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0
    },
    riskLevel: 'Unknown',
    riskScore: 0,
    mitreTechniques: [],
    aiInsights: [],
    executiveSummary: '',
    scanDetails: {},
    technologies: [],
    remediationTimeline: null
  };

  // Extract from scanData API response
  if (scanData) {
    // Vulnerabilities
    if (scanData.vulnerabilities && Array.isArray(scanData.vulnerabilities)) {
      data.vulnerabilities = scanData.vulnerabilities;

      // Calculate stats
      scanData.vulnerabilities.forEach(v => {
        const severity = (v.severity || 'info').toLowerCase();
        data.vulnerabilityStats[severity] = (data.vulnerabilityStats[severity] || 0) + 1;
        data.vulnerabilityStats.total++;
      });
    }

    // Risk assessment
    if (scanData.risk_assessment) {
      data.riskLevel = scanData.risk_assessment.risk_level || 'Unknown';
      data.riskScore = scanData.risk_assessment.overall_risk_score || 0;
    }

    // MITRE techniques
    if (scanData.mitre_mapping && Array.isArray(scanData.mitre_mapping)) {
      data.mitreTechniques = scanData.mitre_mapping;
    }

    // AI insights
    if (scanData.ai_analysis && Array.isArray(scanData.ai_analysis)) {
      data.aiInsights = scanData.ai_analysis;
    }

    // Executive summary
    if (scanData.executive_summary) {
      data.executiveSummary = scanData.executive_summary;
    } else if (scanData.summary) {
      data.executiveSummary = scanData.summary;
    }

    // Scan details
    data.scanDetails = {
      scanType: scanData.scan_type,
      scanMode: scanData.scan_mode,
      duration: scanData.duration,
      status: scanData.status,
      requestsMade: scanData.requests_made,
      pagesScanned: scanData.pages_scanned,
      scannerVersion: scanData.scanner_version
    };

    // Technologies
    if (scanData.technologies && Array.isArray(scanData.technologies)) {
      data.technologies = scanData.technologies;
    }

    // Remediation timeline
    if (scanData.remediation_timeline) {
      data.remediationTimeline = {
        immediate: scanData.remediation_timeline.immediate_action?.items || [],
        shortTerm: scanData.remediation_timeline.short_term?.items || [],
        mediumTerm: scanData.remediation_timeline.medium_term?.items || []
      };
    }
  }

  // Also try to extract from DOM elements (if available)
  try {
    // Vulnerability stats from DOM
    const criticalEl = document.querySelector('.stat-card.coral-bg .stat-card-number');
    const highEl = document.querySelector('.stat-card.pink-bg .stat-card-number');
    const mediumEl = document.querySelector('.stat-card.yellow-bg .stat-card-number');
    const lowEl = document.querySelector('.stat-card.cyan-bg .stat-card-number');

    if (criticalEl) data.vulnerabilityStats.critical = parseInt(criticalEl.textContent) || 0;
    if (highEl) data.vulnerabilityStats.high = parseInt(highEl.textContent) || 0;
    if (mediumEl) data.vulnerabilityStats.medium = parseInt(mediumEl.textContent) || 0;
    if (lowEl) data.vulnerabilityStats.low = parseInt(lowEl.textContent) || 0;

    data.vulnerabilityStats.total = data.vulnerabilityStats.critical + data.vulnerabilityStats.high +
      data.vulnerabilityStats.medium + data.vulnerabilityStats.low;

    // Risk level from DOM
    const riskLevelEl = document.querySelector('.risk-level-badge');
    if (riskLevelEl) {
      data.riskLevel = riskLevelEl.textContent.trim();
    }

    // Executive summary from DOM
    const summaryEl = document.querySelector('.summary-content');
    if (summaryEl && !data.executiveSummary) {
      data.executiveSummary = summaryEl.textContent.trim();
    }
  } catch (e) {
    console.warn('[PDF] Could not extract some data from DOM:', e);
  }

  return data;
}
