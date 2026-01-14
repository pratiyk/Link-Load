import jsPDF from 'jspdf';
import 'jspdf-autotable';

/**
 * LINK&LOAD SECURITY REPORT
 * Complete design matching scan results page with all reference image styling
 */

// PROJECT COLOR PALETTE (exact from scan results)
const COLORS = {
  black: [0, 0, 0],
  cream: [255, 247, 223],        // #FFF7DF
  coral: [255, 107, 107],        // #FF6B6B
  cyan: [109, 212, 217],         // #6DD4D9
  green: [76, 175, 145],         // #4CAF91
  yellow: [255, 217, 61],        // #FFD93D
  pink: [227, 159, 206],         // #E39FCE
  purple: [180, 167, 214],       // #B4A7D6
  blue: [100, 181, 246],         // #64B5F6
  gray: [128, 128, 128],
  lightGray: [200, 200, 200],
  shadowGray: [50, 50, 50],
  darkText: [40, 40, 40],
  white: [255, 255, 255]
};

const FONTS = {
  heading: 'courier',  // VT323 style
  body: 'helvetica'
};

/**
 * PDF Builder matching reference images exactly
 */
class DetailedPDFBuilder {
  constructor(title, subtitle) {
    this.pdf = new jsPDF('p', 'mm', 'a4');
    this.pageWidth = 210;
    this.pageHeight = 297;
    this.margin = 15;
    this.contentWidth = this.pageWidth - (2 * this.margin);
    this.yPos = 50;
    this.pageCount = 1;
    this.title = title;
    this.subtitle = subtitle;

    // Cream background
    this.pdf.setFillColor(...COLORS.cream);
    this.pdf.rect(0, 0, this.pageWidth, this.pageHeight, 'F');

    this.addHeader();
  }

  /**
   * Header
   */
  addHeader() {
    const pdf = this.pdf;

    // Separator line
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(0.5);
    pdf.line(0, 40, this.pageWidth, 40);

    // LINK&LOAD - VT323
    pdf.setFontSize(20);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text('LINK&LOAD', this.margin, 18);

    // Subtitle
    pdf.setFontSize(9);
    pdf.setFont(FONTS.body, 'normal');
    pdf.text('Link. Load. Defend. Repeat.', this.margin, 25);

    // Report title
    pdf.setFontSize(16);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.text('SECURITY SCAN REPORT', this.margin, 35);

    // Page number box (white with border)
    const boxSize = 12;
    const boxX = this.pageWidth - this.margin - boxSize;

    // Shadow
    pdf.setFillColor(200, 200, 200);
    pdf.rect(boxX + 1.5, 15, boxSize, boxSize, 'F');

    // Box
    pdf.setFillColor(...COLORS.white);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1.5);
    pdf.rect(boxX, 14, boxSize, boxSize, 'FD');

    pdf.setFontSize(10);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text(String(this.pageCount), boxX + boxSize / 2, 21.5, { align: 'center' });
  }

  /**
   * Footer
   */
  addFooter() {
    const pdf = this.pdf;
    const y = this.pageHeight - 15;

    // Purple footer
    pdf.setFillColor(...COLORS.purple);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(0.5);
    pdf.rect(0, y, this.pageWidth, 15, 'FD');

    // Text
    pdf.setFontSize(9);
    pdf.setFont(FONTS.body, 'normal');
    pdf.setTextColor(...COLORS.black);
    pdf.text('SECURED BY LINK&LOAD', this.pageWidth / 2, y + 9, { align: 'center' });

    this.addHeader();
  }

  /**
   * Page break
   */
  checkAddPage(spaceNeeded = 50) {
    if (this.yPos + spaceNeeded > this.pageHeight - 25) {
      this.pdf.addPage();
      this.pageCount++;

      this.pdf.setFillColor(...COLORS.cream);
      this.pdf.rect(0, 0, this.pageWidth, this.pageHeight, 'F');

      this.addHeader();
      this.addFooter();
      this.yPos = 50;
    }
  }

  /**
   * Section banner (NO UNDERLINE - matching reference images)
   */
  addSectionBanner(text, pageNum = null) {
    this.checkAddPage(20);
    const pdf = this.pdf;
    const h = 14;

    // Shadow
    pdf.setFillColor(200, 200, 200);
    pdf.rect(this.margin + 2, this.yPos + 2, this.contentWidth, h, 'F');

    // Yellow banner
    pdf.setFillColor(...COLORS.yellow);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1.5);
    pdf.rect(this.margin, this.yPos, this.contentWidth, h, 'FD');

    // Text in VT323 (NO UNDERLINE)
    pdf.setFontSize(12);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text(text.toUpperCase(), this.margin + 5, this.yPos + 9);

    // Page number if provided
    if (pageNum !== null) {
      const boxSize = 10;
      const boxX = this.margin + this.contentWidth - boxSize - 3;

      pdf.setFillColor(...COLORS.white);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(1);
      pdf.rect(boxX, this.yPos + 2, boxSize, boxSize, 'FD');

      pdf.setFontSize(9);
      pdf.text(String(pageNum), boxX + boxSize / 2, this.yPos + 9, { align: 'center' });
    }

    this.yPos += h + 8;
  }

  /**
   * Colored section banner (like ATTACK MATRIX, DEFENSE PLAYBOOK)
   */
  addColoredBanner(text, color, pageNum = null) {
    this.checkAddPage(20);
    const pdf = this.pdf;
    const h = 14;

    // Shadow
    pdf.setFillColor(180, 180, 180);
    pdf.rect(this.margin + 2, this.yPos + 2, this.contentWidth, h, 'F');

    // Colored banner
    pdf.setFillColor(...color);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1.5);
    pdf.rect(this.margin, this.yPos, this.contentWidth, h, 'FD');

    // Black corner square (bottom-right)
    pdf.setFillColor(...COLORS.black);
    pdf.rect(this.margin + this.contentWidth - 4, this.yPos + h - 4, 4, 4, 'F');

    // Text
    pdf.setFontSize(12);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text(text.toUpperCase(), this.margin + 5, this.yPos + 9);

    // Page number box (white)
    if (pageNum !== null) {
      const boxSize = 11;
      const boxX = this.margin + this.contentWidth - boxSize - 10;

      // Shadow
      pdf.setFillColor(180, 180, 180);
      pdf.rect(boxX + 1, this.yPos + 2, boxSize, boxSize, 'F');

      pdf.setFillColor(...COLORS.white);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(1.2);
      pdf.rect(boxX, this.yPos + 1.5, boxSize, boxSize, 'FD');

      pdf.setFontSize(9);
      pdf.setFont(FONTS.heading, 'bold');
      pdf.text(String(pageNum), boxX + boxSize / 2, this.yPos + 9, { align: 'center' });
    }

    this.yPos += h + 10;
  }

  /**
   * Grid of 6 summary cards (2 rows x 3 cols) - matching reference image
   */
  addSummaryGrid(cards) {
    this.checkAddPage(90);
    const pdf = this.pdf;
    const cardW = (this.contentWidth - 8) / 3;
    const cardH = 35;
    const gap = 4;

    cards.forEach((card, i) => {
      const row = Math.floor(i / 3);
      const col = i % 3;
      const x = this.margin + (cardW + gap) * col;
      const y = this.yPos + (cardH + gap) * row;

      // Shadow
      pdf.setFillColor(180, 180, 180);
      pdf.rect(x + 2, y + 2, cardW, cardH, 'F');

      // Card
      pdf.setFillColor(...card.color);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(1.5);
      pdf.rect(x, y, cardW, cardH, 'FD');

      // Black corner square (top-right)
      pdf.setFillColor(...COLORS.black);
      pdf.rect(x + cardW - 5, y, 5, 5, 'F');

      // Number
      pdf.setFontSize(20);
      pdf.setFont(FONTS.heading, 'bold');
      pdf.setTextColor(...COLORS.black);
      pdf.text(String(card.number || ''), x + 5, y + 13);

      // Title
      pdf.setFontSize(8);
      pdf.setFont(FONTS.heading, 'bold');
      const titleLines = pdf.splitTextToSize(card.title.toUpperCase(), cardW - 10);
      titleLines.slice(0, 2).forEach((line, idx) => {
        pdf.text(line, x + 5, y + 20 + (idx * 4));
      });

      // Description
      if (card.description) {
        pdf.setFontSize(7);
        pdf.setFont(FONTS.body, 'normal');
        const descLines = pdf.splitTextToSize(card.description, cardW - 10);
        descLines.slice(0, 1).forEach((line, idx) => {
          pdf.text(line, x + 5, y + 29 + (idx * 3.5));
        });
      }
    });

    this.yPos += (2 * (cardH + gap)) + 5;
  }

  /**
   * Info box with large content area (like executive summary)
   */
  addLargeInfoBox(content, badge = null) {
    this.checkAddPage(60);
    const pdf = this.pdf;
    const boxH = 55;

    // Shadow
    pdf.setFillColor(200, 200, 200);
    pdf.rect(this.margin + 2, this.yPos + 2, this.contentWidth, boxH, 'F');

    // White box
    pdf.setFillColor(...COLORS.white);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1.5);
    pdf.rect(this.margin, this.yPos, this.contentWidth, boxH, 'FD');

    // Badge if provided
    if (badge) {
      const badgeW = 40;
      const badgeH = 8;
      const badgeX = this.margin + this.contentWidth - badgeW - 8;
      const badgeY = this.yPos + 6;

      // Badge shadow
      pdf.setFillColor(180, 180, 180);
      pdf.rect(badgeX + 1, badgeY + 1, badgeW, badgeH, 'F');

      // Badge
      pdf.setFillColor(...COLORS.cyan);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(1);
      pdf.rect(badgeX, badgeY, badgeW, badgeH, 'FD');

      pdf.setFontSize(7);
      pdf.setFont(FONTS.heading, 'bold');
      pdf.setTextColor(...COLORS.black);
      pdf.text(badge.toUpperCase(), badgeX + badgeW / 2, badgeY + 5.5, { align: 'center' });
    }

    // Content
    pdf.setFontSize(9);
    pdf.setFont(FONTS.body, 'normal');
    pdf.setTextColor(...COLORS.darkText);

    const contentX = this.margin + 6;
    const contentY = this.yPos + (badge ? 20 : 10);
    const maxW = this.contentWidth - 12;
    const lines = pdf.splitTextToSize(content, maxW);

    lines.slice(0, 7).forEach((line, i) => {
      pdf.text(line, contentX, contentY + (i * 5));
    });

    this.yPos += boxH + 8;
  }

  /**
   * Detailed vulnerability card (numbered with INFO badge)
   */
  addDetailedVulnCard(vuln, index) {
    this.checkAddPage(55);
    const pdf = this.pdf;
    const cardH = 50;

    // Shadow
    pdf.setFillColor(200, 200, 200);
    pdf.rect(this.margin + 2, this.yPos + 2, this.contentWidth, cardH, 'F');

    // Card with colored background
    const bgColor = this.getSeverityColor(vuln.severity);
    pdf.setFillColor(...bgColor);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1.5);
    pdf.rect(this.margin, this.yPos, this.contentWidth, cardH, 'FD');

    // Black corner square
    pdf.setFillColor(...COLORS.black);
    pdf.rect(this.margin + this.contentWidth - 5, this.yPos, 5, 5, 'F');

    // Number badge (black square with white number)
    const badgeSize = 12;
    pdf.setFillColor(...COLORS.black);
    pdf.rect(this.margin + 5, this.yPos + 5, badgeSize, badgeSize, 'F');

    pdf.setFontSize(10);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.white);
    pdf.text(String(index), this.margin + 5 + badgeSize / 2, this.yPos + 13, { align: 'center' });

    // Severity badge (dynamic based on actual severity)
    const severity = (vuln.severity || 'info').toUpperCase();
    const sevBadgeW = severity === 'CRITICAL' ? 22 : 15;
    const sevBadgeH = 6;
    const sevBadgeX = this.margin + 22;
    const sevBadgeY = this.yPos + 7;

    const sevBadgeColor = this.getSeverityColor(vuln.severity);
    pdf.setFillColor(...sevBadgeColor);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(0.8);
    pdf.rect(sevBadgeX, sevBadgeY, sevBadgeW, sevBadgeH, 'FD');

    pdf.setFontSize(5);
    pdf.setFont(FONTS.body, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text(severity, sevBadgeX + sevBadgeW / 2, sevBadgeY + 4, { align: 'center' });

    // Title
    pdf.setFontSize(10);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    const title = String(vuln.name || vuln.title || 'SECURITY ISSUE');
    pdf.text(title.toUpperCase().substring(0, 60), this.margin + 5, this.yPos + 25);

    // Description
    if (vuln.description) {
      pdf.setFontSize(8);
      pdf.setFont(FONTS.body, 'normal');
      const desc = vuln.description.substring(0, 200);
      const lines = pdf.splitTextToSize(desc, this.contentWidth - 15);
      lines.slice(0, 3).forEach((line, i) => {
        pdf.text(line, this.margin + 5, this.yPos + 32 + (i * 4));
      });
    }

    // White input field at bottom (like CVSS, Location)
    if (vuln.cvss_score || vuln.severity) {
      const fieldY = this.yPos + cardH - 8;
      pdf.setFillColor(...COLORS.white);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(0.8);
      pdf.rect(this.margin + 5, fieldY, 50, 5, 'FD');

      pdf.setFontSize(6);
      pdf.setFont(FONTS.body, 'normal');
      pdf.setTextColor(...COLORS.black);
      const cvssText = vuln.cvss_score ? `CVSS: ${vuln.cvss_score}` : `Severity: ${vuln.severity}`;
      pdf.text(cvssText, this.margin + 7, fieldY + 3.5);
    }

    this.yPos += cardH + 6;
  }

  /**
   * Metric cards (4 per row) - like Defense Playbook
   */
  addMetricCards(cards) {
    this.checkAddPage(35);
    const pdf = this.pdf;
    const cardW = (this.contentWidth - 12) / 4;
    const cardH = 30;
    const gap = 4;

    cards.forEach((card, i) => {
      const x = this.margin + (cardW + gap) * i;

      // Shadow
      pdf.setFillColor(180, 180, 180);
      pdf.rect(x + 2, this.yPos + 2, cardW, cardH, 'F');

      // Card
      pdf.setFillColor(...card.color);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(1.5);
      pdf.rect(x, this.yPos, cardW, cardH, 'FD');

      // Black corner
      pdf.setFillColor(...COLORS.black);
      pdf.rect(x + cardW - 4, this.yPos, 4, 4, 'F');

      // Value
      pdf.setFontSize(16);
      pdf.setFont(FONTS.heading, 'bold');
      pdf.setTextColor(...COLORS.black);
      pdf.text(String(card.value || ''), x + cardW / 2, this.yPos + 14, { align: 'center' });

      // Label
      pdf.setFontSize(7);
      pdf.setFont(FONTS.heading, 'bold');
      const labelLines = pdf.splitTextToSize(card.label.toUpperCase(), cardW - 6);
      labelLines.slice(0, 2).forEach((line, idx) => {
        pdf.text(line, x + cardW / 2, this.yPos + 22 + (idx * 3.5), { align: 'center' });
      });
    });

    this.yPos += cardH + 8;
  }

  /**
   * Horizontal bar chart (like threat distribution)
   */
  addHorizontalBar(label, value, maxValue, color) {
    this.checkAddPage(15);
    const pdf = this.pdf;
    const barH = 10;
    const barW = this.contentWidth - 80;
    const fillW = (value / maxValue) * barW;

    // Label badge
    const labelW = 20;
    pdf.setFillColor(...COLORS.cyan);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1);
    pdf.rect(this.margin, this.yPos, labelW, barH, 'FD');

    pdf.setFontSize(7);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text(label.toUpperCase(), this.margin + labelW / 2, this.yPos + 6.5, { align: 'center' });

    // Bar shadow
    pdf.setFillColor(200, 200, 200);
    pdf.rect(this.margin + labelW + 5 + 1, this.yPos + 1, fillW, barH, 'F');

    // Bar
    pdf.setFillColor(...color);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1);
    pdf.rect(this.margin + labelW + 5, this.yPos, fillW, barH, 'FD');

    // Value
    pdf.setFontSize(9);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.text(String(value), this.margin + this.contentWidth - 15, this.yPos + 6.5);

    this.yPos += barH + 5;
  }

  /**
   * MITRE technique box (yellow header, white content)
   */
  addTechniqueBox(technique, index) {
    this.checkAddPage(45);
    const pdf = this.pdf;
    const boxW = (this.contentWidth - 6) / 2;
    const boxH = 40;
    const x = this.margin + ((index % 2) * (boxW + 6));

    if (index % 2 === 0) {
      // Start new row
    }

    // Yellow header
    pdf.setFillColor(...COLORS.yellow);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1.5);
    pdf.rect(x, this.yPos, boxW, 8, 'FD');

    pdf.setFontSize(7);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text(`TECHNIQUE ${index + 1}:`, x + 3, this.yPos + 5.5);

    // White content area
    pdf.setFillColor(...COLORS.white);
    pdf.setDrawColor(...COLORS.black);
    pdf.rect(x, this.yPos + 8, boxW, boxH - 8, 'FD');

    // Technique ID badge
    const idBadgeW = 25;
    const idBadgeH = 7;
    pdf.setFillColor(...COLORS.cyan);
    pdf.setLineWidth(0.8);
    pdf.rect(x + 3, this.yPos + 13, idBadgeW, idBadgeH, 'FD');

    pdf.setFontSize(8);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.text(String(technique.technique_id || 'T1234'), x + 3 + idBadgeW / 2, this.yPos + 18, { align: 'center' });

    // Technique name
    pdf.setFontSize(9);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    const name = String(technique.name || 'Technique Name');
    pdf.text(name.toUpperCase().substring(0, 30), x + 3, this.yPos + 28);

    // Tactic
    pdf.setFontSize(7);
    pdf.setFont(FONTS.body, 'normal');
    pdf.text(`Tactic: ${String(technique.tactic || 'Unknown').toUpperCase()}`, x + 3, this.yPos + 35);

    if (index % 2 === 1) {
      this.yPos += boxH + 5;
    }
  }

  /**
   * Timeline table (yellow header)
   */
  addTimelineTable(items) {
    this.checkAddPage(60);
    const pdf = this.pdf;

    // Yellow header
    const headerH = 10;
    pdf.setFillColor(...COLORS.yellow);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1.5);
    pdf.rect(this.margin, this.yPos, this.contentWidth, headerH, 'FD');

    pdf.setFontSize(9);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text('REMEDIATION TIMELINE', this.margin + 5, this.yPos + 7);

    this.yPos += headerH;

    // Content rows
    const rowH = 12;
    items.slice(0, 3).forEach((item, i) => {
      // White row
      const fillColor = i % 2 === 0 ? COLORS.white : COLORS.cream;
      pdf.setFillColor(...fillColor);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(0.8);
      pdf.rect(this.margin, this.yPos, this.contentWidth, rowH, 'FD');

      // Content
      pdf.setFontSize(8);
      pdf.setFont(FONTS.body, 'normal');
      pdf.setTextColor(...COLORS.darkText);
      pdf.text(String(item.title || 'Action item'), this.margin + 5, this.yPos + 8);

      // Duration
      pdf.setFont(FONTS.heading, 'bold');
      pdf.text(String(item.duration || '1 week'), this.margin + this.contentWidth - 25, this.yPos + 8);

      this.yPos += rowH;
    });

    this.yPos += 8;
  }

  /**
   * Cost comparison bars
   */
  addCostComparison(fixNow, riskExposure) {
    this.checkAddPage(50);
    const pdf = this.pdf;

    // Title
    pdf.setFontSize(10);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text('COST COMPARISON', this.margin, this.yPos);
    this.yPos += 8;

    const barH = 12;
    const barW = this.contentWidth - 60;

    // Fix Now bar
    pdf.setFontSize(8);
    pdf.setFont(FONTS.body, 'normal');
    pdf.text('Fix Now', this.margin, this.yPos + 6);
    pdf.text(`₹${fixNow.toLocaleString()}`, this.margin, this.yPos + 11);

    const fixPercent = (fixNow / riskExposure) * 100;
    const fixW = (fixPercent / 100) * barW;

    pdf.setFillColor(...COLORS.green);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1);
    pdf.rect(this.margin + 50, this.yPos, fixW, barH, 'FD');

    pdf.setFont(FONTS.heading, 'bold');
    pdf.text(`${Math.round(fixPercent)}%`, this.margin + 50 + barW + 5, this.yPos + 8);

    this.yPos += barH + 5;

    // Risk Exposure bar
    pdf.setFont(FONTS.body, 'normal');
    pdf.text('Risk Exposure', this.margin, this.yPos + 6);
    pdf.text(`₹${riskExposure.toLocaleString()}`, this.margin, this.yPos + 11);

    pdf.setFillColor(...COLORS.coral);
    pdf.rect(this.margin + 50, this.yPos, barW, barH, 'FD');

    pdf.setFont(FONTS.heading, 'bold');
    pdf.text('100%', this.margin + 50 + barW + 5, this.yPos + 8);

    this.yPos += barH + 10;
  }

  /**
   * ROI box (large yellow box)
   */
  addROIBox(roi) {
    this.checkAddPage(35);
    const pdf = this.pdf;
    const boxH = 30;

    // Shadow
    pdf.setFillColor(200, 200, 200);
    pdf.rect(this.margin + 2, this.yPos + 2, this.contentWidth, boxH, 'F');

    // Yellow box
    pdf.setFillColor(...COLORS.yellow);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1.5);
    pdf.rect(this.margin, this.yPos, this.contentWidth, boxH, 'FD');

    // ROI value
    pdf.setFontSize(24);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text(`${roi}%`, this.margin + this.contentWidth / 2, this.yPos + 15, { align: 'center' });

    // Label
    pdf.setFontSize(9);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.text('RETURN ON INVESTMENT', this.margin + this.contentWidth / 2, this.yPos + 24, { align: 'center' });

    this.yPos += boxH + 8;
  }

  addText(text, options = {}) {
    this.checkAddPage();
    const pdf = this.pdf;

    pdf.setFontSize(options.size || 9);
    pdf.setFont(options.font || FONTS.body, options.bold ? 'bold' : 'normal');
    pdf.setTextColor(...(options.color || COLORS.darkText));

    const indent = options.indent || 0;
    const maxWidth = this.contentWidth - indent - 5;
    const lines = pdf.splitTextToSize(text, maxWidth);

    lines.forEach(line => {
      this.checkAddPage();
      pdf.text(line, this.margin + indent, this.yPos);
      this.yPos += options.lineHeight || 5;
    });
  }

  addSpace(mm) {
    this.yPos += mm;
  }

  addKeyValue(key, value) {
    this.checkAddPage();
    const pdf = this.pdf;

    pdf.setFontSize(9);
    pdf.setFont(FONTS.body, 'bold');
    pdf.setTextColor(...COLORS.darkText);
    pdf.text(`${key}:`, this.margin, this.yPos);

    pdf.setFont(FONTS.body, 'normal');
    pdf.setTextColor(...COLORS.gray);
    const valueX = this.margin + 50;
    const maxWidth = this.contentWidth - 50;
    const lines = pdf.splitTextToSize(String(value), maxWidth);
    lines.forEach((line, i) => {
      pdf.text(line, valueX, this.yPos + (i * 5));
    });

    this.yPos += Math.max(5, lines.length * 5);
  }

  getSeverityColor(severity) {
    const s = (severity || 'info').toLowerCase();
    return {
      critical: COLORS.coral,
      high: COLORS.coral,
      medium: COLORS.yellow,
      low: COLORS.cyan,
      info: COLORS.purple,
      unknown: COLORS.gray
    }[s] || COLORS.cyan;
  }

  /**
   * Finalize
   */
  finalize() {
    // Add footer to first page
    this.pdf.setPage(1);
    const y = this.pageHeight - 15;
    this.pdf.setFillColor(...COLORS.purple);
    this.pdf.setDrawColor(...COLORS.black);
    this.pdf.setLineWidth(0.5);
    this.pdf.rect(0, y, this.pageWidth, 15, 'FD');

    this.pdf.setFontSize(9);
    this.pdf.setFont(FONTS.body, 'normal');
    this.pdf.setTextColor(...COLORS.black);
    this.pdf.text('SECURED BY LINK&LOAD', this.pageWidth / 2, y + 9, { align: 'center' });

    // Update page numbers
    const total = this.pdf.internal.pages.length - 1;
    for (let i = 1; i <= total; i++) {
      this.pdf.setPage(i);
      const boxSize = 12;
      const boxX = this.pageWidth - this.margin - boxSize;

      // Shadow
      this.pdf.setFillColor(200, 200, 200);
      this.pdf.rect(boxX + 1.5, 15, boxSize, boxSize, 'F');

      // Box
      this.pdf.setFillColor(...COLORS.white);
      this.pdf.setDrawColor(...COLORS.black);
      this.pdf.setLineWidth(1.5);
      this.pdf.rect(boxX, 14, boxSize, boxSize, 'FD');

      this.pdf.setFontSize(10);
      this.pdf.setFont(FONTS.heading, 'bold');
      this.pdf.setTextColor(...COLORS.black);
      this.pdf.text(String(i), boxX + boxSize / 2, 21.5, { align: 'center' });
    }

    return this.pdf;
  }
}

/**
 * Extract data
 */
const extractAllScanData = (scanData) => {
  if (!scanData) return {};

  const vulnerabilities = scanData.vulnerabilities || [];

  // Calculate vulnerability stats for dynamic summary
  const stats = {
    critical: vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'critical').length,
    high: vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'high').length,
    medium: vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'medium').length,
    low: vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'low').length,
    info: vulnerabilities.filter(v => (v.severity || '').toLowerCase() === 'info').length,
    total: vulnerabilities.length
  };

  // Extract risk data from both possible locations
  const riskScore = scanData.risk_score || scanData.risk_assessment?.overall_risk_score || 0.0;
  const riskLevel = scanData.risk_level || scanData.risk_assessment?.risk_level || 'Unknown';

  // Generate fully dynamic executive summary based on ACTUAL scan results
  // Match the scan results page logic: executive_summary is a plain string from backend
  let executiveSummary = scanData.executive_summary || scanData.summary || scanData.ai_summary;

  // If no executive summary exists, generate one dynamically
  if (!executiveSummary) {
    const urgentCount = stats.critical + stats.high;
    const totalFindings = stats.total;

    if (urgentCount > 0) {
      executiveSummary = `The security assessment identified ${totalFindings} finding${totalFindings !== 1 ? 's' : ''} across the target application, with ${stats.critical} critical and ${stats.high} high-severity vulnerabilities requiring immediate attention. The overall risk score of ${riskScore.toFixed(1)}/10 reflects a ${riskLevel.toLowerCase()} risk posture. Key concerns include ${stats.critical > 0 ? 'critical vulnerabilities that could lead to system compromise' : 'high-priority security issues'}, ${stats.medium} medium-severity issues, and ${stats.low + stats.info} informational findings. Immediate remediation is recommended for critical and high-severity issues to reduce attack surface and prevent potential exploitation.`;
    } else if (stats.medium > 0) {
      executiveSummary = `The security assessment of the target application revealed ${totalFindings} finding${totalFindings !== 1 ? 's' : ''}, with no critical or high-severity vulnerabilities detected. The risk score of ${riskScore.toFixed(1)}/10 indicates a ${riskLevel.toLowerCase()} risk posture. The scan identified ${stats.medium} medium-severity issue${stats.medium !== 1 ? 's' : ''}, ${stats.low} low-severity finding${stats.low !== 1 ? 's' : ''}, and ${stats.info} informational observation${stats.info !== 1 ? 's' : ''}. While no immediate threats were discovered, addressing medium-severity issues will strengthen the security posture and reduce potential attack vectors.`;
    } else {
      executiveSummary = `The security assessment demonstrates a strong security posture for the target application. The scan identified ${totalFindings} finding${totalFindings !== 1 ? 's' : ''}, all classified as ${stats.low > 0 ? 'low-severity or informational' : 'informational'}. The risk score of ${riskScore.toFixed(1)}/10 reflects a ${riskLevel.toLowerCase()} risk profile. These findings primarily relate to security best practices, configuration improvements, and informational disclosures. No critical, high, or medium-severity vulnerabilities were detected, indicating effective security controls are in place.`;
    }
  }

  const scanDetails = {
    scanId: scanData.scan_id || scanData.id,
    scanType: scanData.scan_type || 'Full Security Scan',
    scanMode: scanData.scan_mode || 'Standard',
    scanners: scanData.scanners || [],
    duration: scanData.duration || 'N/A',
    startedAt: scanData.started_at,
    completedAt: scanData.completed_at,
    status: scanData.status,
    targetUrl: scanData.target_url || scanData.url,
    riskScore: riskScore,
    riskLevel: riskLevel
  };

  const technologies = scanData.technologies || [];
  const mitreTechniques = scanData.mitre_mapping || [];
  const threatIntel = scanData.threat_intel || {};
  const realtimeIntel = scanData.realtime_intel || [];
  const recommendations = scanData.recommendations || [];

  // Enhanced risk assessment with all fields
  const riskAssessment = {
    overall_risk_score: riskScore,
    risk_level: riskLevel,
    vulnerability_count: stats.total,
    critical_count: stats.critical,
    high_count: stats.high,
    medium_count: stats.medium,
    low_count: stats.low,
    info_count: stats.info,
    ...(scanData.risk_assessment || {})
  };

  const remediationStrategies = scanData.remediation_strategies || {};

  return {
    vulnerabilities,
    executiveSummary,
    scanDetails,
    technologies,
    mitreTechniques,
    threatIntel,
    realtimeIntel,
    recommendations,
    riskAssessment,
    remediationStrategies
  };
};

/**
 * MAIN PDF GENERATION
 */
export const generateScanResultsPDF = async (scanId, targetUrl, scanData) => {
  try {
    console.log('[PDF] Generating detailed report...', { scanId, targetUrl });

    const builder = new DetailedPDFBuilder('SECURITY SCAN REPORT', targetUrl);
    const data = extractAllScanData(scanData);

    // Calculate statistics
    const vulns = data.vulnerabilities || [];
    const stats = {
      total: vulns.length,
      critical: vulns.filter(v => (v.severity || '').toLowerCase() === 'critical').length,
      high: vulns.filter(v => (v.severity || '').toLowerCase() === 'high').length,
      medium: vulns.filter(v => (v.severity || '').toLowerCase() === 'medium').length,
      low: vulns.filter(v => (v.severity || '').toLowerCase() === 'low').length,
      info: vulns.filter(v => (v.severity || '').toLowerCase() === 'info').length
    };

    // ===========================================
    // SCAN DETAILS (FIRST PAGE)
    // ===========================================
    builder.addSectionBanner('Scan Results');
    builder.addSpace(8);

    // SCAN OVERVIEW heading
    builder.addText('SCAN OVERVIEW', { bold: true, size: 10, font: FONTS.heading });
    builder.addSpace(8);

    // Scan details in 3-column grid
    const firstPagePdf = builder.pdf;
    const infoItemW = (builder.contentWidth - 15) / 3;
    const infoItemH = 20;
    let infoX = builder.margin;
    let infoY = builder.yPos;

    // Format scanners dynamically
    const scannersDisplay = data.scanDetails.scanners && data.scanDetails.scanners.length > 0
      ? data.scanDetails.scanners.map(s => s.toUpperCase()).join(' + ')
      : 'OWASP ZAP + Nuclei + Wapiti';

    const scanInfo = [
      { label: 'TARGET', value: data.scanDetails.targetUrl || targetUrl || 'N/A' },
      { label: 'SCAN MODE', value: (data.scanDetails.scanMode || 'Standard').toUpperCase() },
      { label: 'SCANNERS', value: scannersDisplay },
      { label: 'DURATION', value: data.scanDetails.duration || 'N/A' },
      { label: 'SCAN ID', value: data.scanDetails.scanId || scanId || 'N/A' },
      { label: 'STARTED', value: data.scanDetails.startedAt ? new Date(data.scanDetails.startedAt).toLocaleString() : 'N/A' },
      { label: 'COMPLETED', value: data.scanDetails.completedAt ? new Date(data.scanDetails.completedAt).toLocaleString() : 'N/A' },
      { label: 'STATUS', value: (data.scanDetails.status || 'Completed').toUpperCase() }
    ];

    scanInfo.forEach((item, i) => {
      const col = i % 3;
      if (col === 0 && i > 0) {
        infoY += infoItemH + 5;
      }
      infoX = builder.margin + (col * (infoItemW + 7.5));

      // Shadow
      firstPagePdf.setFillColor(200, 200, 200);
      firstPagePdf.rect(infoX + 1.5, infoY + 1.5, infoItemW, infoItemH, 'F');

      // White box
      firstPagePdf.setFillColor(...COLORS.white);
      firstPagePdf.setDrawColor(...COLORS.black);
      firstPagePdf.setLineWidth(1.5);
      firstPagePdf.rect(infoX, infoY, infoItemW, infoItemH, 'FD');

      // Black corner
      firstPagePdf.setFillColor(...COLORS.black);
      firstPagePdf.rect(infoX + infoItemW - 4, infoY, 4, 4, 'F');

      // Label
      firstPagePdf.setFont(FONTS.heading, 'bold');
      firstPagePdf.setFontSize(7);
      firstPagePdf.setTextColor(...COLORS.black);
      firstPagePdf.text(item.label, infoX + 4, infoY + 6);

      // Value
      firstPagePdf.setFont(FONTS.body, 'normal');
      firstPagePdf.setFontSize(8);
      const valueLines = firstPagePdf.splitTextToSize(String(item.value), infoItemW - 8);
      valueLines.slice(0, 2).forEach((line, lineIdx) => {
        firstPagePdf.text(line, infoX + 4, infoY + 12 + (lineIdx * 4));
      });
    });

    builder.yPos = infoY + infoItemH + 5;

    // ===========================================
    // MISSION BRIEF (NEW PAGE)
    // ===========================================
    builder.pdf.addPage();
    builder.pageCount++;
    builder.pdf.setFillColor(...COLORS.cream);
    builder.pdf.rect(0, 0, builder.pageWidth, builder.pageHeight, 'F');
    builder.addHeader();
    builder.addFooter();
    builder.yPos = 50;

    builder.addSectionBanner('Mission Brief');

    // 6 Summary cards grid
    builder.addSummaryGrid([
      {
        number: '01',
        title: 'Critical Issues',
        description: stats.critical > 0 ? `${stats.critical} critical vulnerabilities detected` : 'No critical vulnerabilities detected in this scan',
        color: COLORS.cyan
      },
      {
        number: '02',
        title: 'High Priority',
        description: stats.high > 0 ? `${stats.high} high-severity issues reported` : 'No high-severity issues were reported',
        color: COLORS.coral
      },
      {
        number: '03',
        title: 'Medium & Low Risk',
        description: stats.medium + stats.low > 0 ? `${stats.medium + stats.low} issues identified` : 'Medium and low risk surfaces are currently clear',
        color: COLORS.green
      },
      {
        number: '04',
        title: 'Threat Intelligence',
        description: (() => {
          const ti = data.threatIntel;
          if (ti && ti.reputation) {
            const repLevel = ti.reputation.risk_level || 'Unknown';
            const repScore = ti.reputation.score !== undefined ? ti.reputation.score : 'N/A';
            return `Reputation: ${repLevel} (Score: ${repScore})`;
          }
          return 'Reputation: Not Available';
        })(),
        color: COLORS.purple
      },
      {
        number: '05',
        title: 'Coverage & Mapping',
        description: data.mitreTechniques && data.mitreTechniques.length > 0
          ? `${data.mitreTechniques.length} MITRE ATT&CK technique${data.mitreTechniques.length !== 1 ? 's' : ''} mapped`
          : 'No MITRE techniques mapped',
        color: COLORS.pink
      },
      {
        number: '06',
        title: 'AI Analysis',
        description: (() => {
          const aiAnalysis = scanData.ai_analysis;
          if (aiAnalysis && Array.isArray(aiAnalysis) && aiAnalysis.length > 0) {
            return `${aiAnalysis.length} AI-generated insight${aiAnalysis.length !== 1 ? 's' : ''} available`;
          } else if (data.recommendations && data.recommendations.length > 0) {
            return `${data.recommendations.length} recommendation${data.recommendations.length !== 1 ? 's' : ''} generated`;
          }
          return 'AI analysis completed';
        })(),
        color: COLORS.yellow
      }
    ]);

    // Full Executive Summary (not truncated) - Dynamic with page breaks
    const pdf = builder.pdf;
    const maxW = builder.contentWidth - 12;
    const lineHeight = 5;
    const summaryStartY = builder.yPos;

    // Badge
    const badgeW = 50;
    const badgeH = 9;
    const badgeX = builder.margin + builder.contentWidth - badgeW - 8;
    const badgeY = builder.yPos + 6;

    pdf.setFillColor(180, 180, 180);
    pdf.rect(badgeX + 1, badgeY + 1, badgeW, badgeH, 'F');

    pdf.setFillColor(...COLORS.cyan);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1);
    pdf.rect(badgeX, badgeY, badgeW, badgeH, 'FD');

    pdf.setFontSize(7);
    pdf.setFont(FONTS.heading, 'bold');
    pdf.setTextColor(...COLORS.black);
    pdf.text('GROQ LLM - CACHED', badgeX + badgeW / 2, badgeY + 6, { align: 'center' });

    // Split text into lines
    pdf.setFontSize(9);
    pdf.setFont(FONTS.body, 'normal');
    pdf.setTextColor(...COLORS.darkText);
    const lines = pdf.splitTextToSize(data.executiveSummary, maxW);

    // Calculate total height needed
    const totalTextHeight = lines.length * lineHeight + 30; // 30 = padding top/bottom
    const availableHeight = builder.pageHeight - builder.yPos - builder.margin - 10;

    let boxH;
    if (totalTextHeight > availableHeight) {
      // Text spans multiple pages - draw box to bottom of current page
      boxH = availableHeight;
    } else {
      // Text fits on current page
      boxH = totalTextHeight;
    }

    // Shadow
    pdf.setFillColor(200, 200, 200);
    pdf.rect(builder.margin + 2, builder.yPos + 2, builder.contentWidth, boxH, 'F');

    // White box
    pdf.setFillColor(...COLORS.white);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1.5);
    pdf.rect(builder.margin, builder.yPos, builder.contentWidth, boxH, 'FD');

    // Render all lines with automatic page breaks
    const contentX = builder.margin + 6;
    let currentY = builder.yPos + 20;

    lines.forEach((line, i) => {
      // Check if we need a new page
      if (currentY > builder.pageHeight - builder.margin - 10) {
        // Add new page
        builder.pdf.addPage();
        builder.pageCount++;
        builder.pdf.setFillColor(...COLORS.cream);
        builder.pdf.rect(0, 0, builder.pageWidth, builder.pageHeight, 'F');
        builder.addHeader();
        builder.addFooter();

        // Continue box on new page
        currentY = 50;
        const newBoxH = Math.min(
          (lines.length - i) * lineHeight + 20,
          builder.pageHeight - currentY - builder.margin - 10
        );

        // Shadow
        pdf.setFillColor(200, 200, 200);
        pdf.rect(builder.margin + 2, currentY + 2, builder.contentWidth, newBoxH, 'F');

        // White box continuation
        pdf.setFillColor(...COLORS.white);
        pdf.setDrawColor(...COLORS.black);
        pdf.setLineWidth(1.5);
        pdf.rect(builder.margin, currentY, builder.contentWidth, newBoxH, 'FD');

        currentY += 10;

        // Reset font after page break
        pdf.setFontSize(9);
        pdf.setFont(FONTS.body, 'normal');
        pdf.setTextColor(...COLORS.darkText);
      }

      pdf.text(line, contentX, currentY);
      currentY += lineHeight;
    });

    builder.yPos = currentY + 10;

    // ===========================================
    // RECON REPORT (NEW PAGE)
    // ===========================================
    builder.pdf.addPage();
    builder.pageCount++;
    builder.pdf.setFillColor(...COLORS.cream);
    builder.pdf.rect(0, 0, builder.pageWidth, builder.pageHeight, 'F');
    builder.addHeader();
    builder.addFooter();
    builder.yPos = 50;

    builder.addSectionBanner('Recon Report - Intelligence Overview');

    // 6 Overview Cards
    const overviewCards = [
      {
        number: '01',
        title: 'Critical Issues',
        description: stats.critical ? `${stats.critical} critical ${stats.critical === 1 ? 'vulnerability' : 'vulnerabilities'} detected` : 'No critical vulnerabilities detected',
        color: COLORS.cyan
      },
      {
        number: '02',
        title: 'High Priority',
        description: stats.high ? `${stats.high} high-severity ${stats.high === 1 ? 'issue' : 'issues'} reported` : 'No high-severity issues reported',
        color: COLORS.coral
      },
      {
        number: '03',
        title: 'Medium & Low Risk',
        description: `${stats.medium + stats.low} medium and low risk surfaces detected`,
        color: COLORS.green
      },
      {
        number: '04',
        title: 'Threat Intelligence',
        description: data.threatIntel.reputation ? `Reputation: ${data.threatIntel.reputation.score || 0}/100` : 'External intelligence sources queried',
        color: COLORS.purple
      },
      {
        number: '05',
        title: 'Coverage & Mapping',
        description: `${data.mitreTechniques.length} MITRE techniques mapped to help trace attack paths`,
        color: COLORS.pink
      },
      {
        number: '06',
        title: 'AI Insights',
        description: `${data.realtimeIntel.length} curated insights ready to guide remediation`,
        color: COLORS.yellow
      }
    ];

    builder.addSummaryGrid(overviewCards);

    // Risk Score Display - Use actual scan data
    const reconRiskScore = data.scanDetails.riskScore || data.riskAssessment?.overall_risk_score || 0;
    const reconRiskLevel = (data.scanDetails.riskLevel || data.riskAssessment?.risk_level || 'Unknown').toUpperCase();

    builder.addText('RISK ASSESSMENT', { bold: true, size: 10, font: FONTS.heading });
    builder.addSpace(4);

    const reconPdf = builder.pdf;
    const riskBoxW = 60;
    const riskBoxH = 30;
    const riskBoxX = builder.margin + (builder.contentWidth - riskBoxW) / 2;
    const riskBoxY = builder.yPos;

    // Shadow
    reconPdf.setFillColor(200, 200, 200);
    reconPdf.rect(riskBoxX + 2, riskBoxY + 2, riskBoxW, riskBoxH, 'F');

    // Risk score box
    const reconRiskColor = reconRiskScore > 7 ? COLORS.coral : reconRiskScore > 4 ? COLORS.yellow : COLORS.green;
    reconPdf.setFillColor(...reconRiskColor);
    reconPdf.setDrawColor(...COLORS.black);
    reconPdf.setLineWidth(1.5);
    reconPdf.rect(riskBoxX, riskBoxY, riskBoxW, riskBoxH, 'FD');

    // Black corner
    reconPdf.setFillColor(...COLORS.black);
    reconPdf.rect(riskBoxX + riskBoxW - 5, riskBoxY, 5, 5, 'F');

    // Score text
    reconPdf.setFont(FONTS.heading, 'bold');
    reconPdf.setFontSize(24);
    reconPdf.setTextColor(...COLORS.black);
    reconPdf.text(String(reconRiskScore.toFixed(1)), riskBoxX + riskBoxW / 2, riskBoxY + 15, { align: 'center' });

    reconPdf.setFont(FONTS.body, 'normal');
    reconPdf.setFontSize(9);
    reconPdf.text(`${reconRiskLevel} RISK`, riskBoxX + riskBoxW / 2, riskBoxY + 23, { align: 'center' });

    builder.yPos += riskBoxH + 10;

    // Threat Intelligence Sources
    const ti = data.threatIntel || {};
    if (ti.reputation || ti.virustotal || ti.google_safe_browsing || ti.abuseipdb || ti.shodan) {
      builder.addText('EXTERNAL INTELLIGENCE SOURCES', { bold: true, size: 10, font: FONTS.heading });
      builder.addSpace(6);

      const sources = [];

      if (ti.reputation && ti.reputation.score !== undefined) {
        sources.push({
          name: 'Reputation Score',
          value: `${ti.reputation.score}/100`,
          detail: `${ti.reputation.risk_level || 'Unknown'} • ${ti.reputation.sources_checked || 0} sources`,
          color: ti.reputation.score >= 70 ? COLORS.green : ti.reputation.score >= 40 ? COLORS.yellow : COLORS.coral
        });
      }

      if (ti.virustotal) {
        const vt = ti.virustotal;
        sources.push({
          name: 'VirusTotal',
          value: vt.malicious > 0 ? `${vt.malicious} Malicious` : vt.suspicious > 0 ? `${vt.suspicious} Suspicious` : 'Clean',
          detail: `${vt.total_engines || 0} engines scanned`,
          color: vt.malicious > 0 ? COLORS.coral : vt.suspicious > 0 ? COLORS.yellow : COLORS.green
        });
      }

      if (ti.google_safe_browsing && ti.google_safe_browsing.status) {
        const gsb = ti.google_safe_browsing;
        sources.push({
          name: 'Safe Browsing',
          value: gsb.is_flagged ? 'FLAGGED' : 'Safe',
          detail: gsb.is_flagged ? (gsb.threat_types?.join(', ') || 'Threat detected') : 'No threats found',
          color: gsb.is_flagged ? COLORS.coral : COLORS.green
        });
      }

      if (ti.abuseipdb && ti.abuseipdb.ip_address) {
        const abuse = ti.abuseipdb;
        sources.push({
          name: 'AbuseIPDB',
          value: `${abuse.abuse_confidence_score || 0}%`,
          detail: `${abuse.total_reports || 0} reports • ${abuse.isp || 'Unknown ISP'}`,
          color: abuse.abuse_confidence_score > 50 ? COLORS.coral : abuse.abuse_confidence_score > 25 ? COLORS.yellow : COLORS.green
        });
      }

      if (ti.shodan && ti.shodan.ip) {
        const shodan = ti.shodan;
        sources.push({
          name: 'Shodan',
          value: `${shodan.open_ports_count || 0} Ports`,
          detail: `${shodan.vuln_count || 0} vulns • ${shodan.services?.length || 0} services`,
          color: shodan.vuln_count > 0 ? COLORS.coral : COLORS.cyan
        });
      }

      if (ti.securitytrails && ti.securitytrails.subdomains_count !== undefined) {
        const st = ti.securitytrails;
        sources.push({
          name: 'SecurityTrails',
          value: `${st.subdomains_count || 0} Subdomains`,
          detail: `DNS records: ${st.dns_records_count || 0}`,
          color: COLORS.blue
        });
      }

      // Display source cards in 2-column grid
      const intelCardH = 22;
      const intelCardW = (builder.contentWidth - 6) / 2;

      sources.forEach((source, i) => {
        const isLeft = i % 2 === 0;
        const cardX = builder.margin + (isLeft ? 0 : intelCardW + 6);
        const cardY = builder.yPos;

        if (isLeft && i > 0) {
          builder.yPos += intelCardH + 4;
        }

        // Shadow
        reconPdf.setFillColor(200, 200, 200);
        reconPdf.rect(cardX + 1.5, cardY + 1.5, intelCardW, intelCardH, 'F');

        // Card background
        reconPdf.setFillColor(...source.color);
        reconPdf.setDrawColor(...COLORS.black);
        reconPdf.setLineWidth(1.5);
        reconPdf.rect(cardX, cardY, intelCardW, intelCardH, 'FD');

        // Black corner
        reconPdf.setFillColor(...COLORS.black);
        reconPdf.rect(cardX + intelCardW - 4, cardY, 4, 4, 'F');

        // Source name
        reconPdf.setFont(FONTS.heading, 'bold');
        reconPdf.setFontSize(8);
        reconPdf.setTextColor(...COLORS.black);
        reconPdf.text(source.name.toUpperCase(), cardX + 3, cardY + 6);

        // Value
        reconPdf.setFont(FONTS.heading, 'bold');
        reconPdf.setFontSize(11);
        reconPdf.text(String(source.value), cardX + 3, cardY + 13);

        // Detail
        reconPdf.setFont(FONTS.body, 'normal');
        reconPdf.setFontSize(7);
        const detailLines = reconPdf.splitTextToSize(source.detail, intelCardW - 6);
        reconPdf.text(detailLines[0], cardX + 3, cardY + 18);

        if (!isLeft) {
          builder.yPos += intelCardH + 4;
        }
      });

      // Handle odd number of sources
      if (sources.length % 2 === 1) {
        builder.yPos += intelCardH + 4;
      }
    }

    // ===========================================
    // THREAT CATALOG (NEW PAGE)
    // ===========================================
    builder.pdf.addPage();
    builder.pageCount++;
    builder.pdf.setFillColor(...COLORS.cream);
    builder.pdf.rect(0, 0, builder.pageWidth, builder.pageHeight, 'F');
    builder.addHeader();
    builder.addFooter();
    builder.yPos = 50;

    builder.addSectionBanner('Threat Catalog - Vulnerability Database');

    if (vulns.length > 0) {
      builder.addText(`DISCOVERED ${vulns.length} VULNERABILITIES`, {
        bold: true,
        size: 11,
        font: FONTS.heading
      });
      builder.addSpace(8);

      // Show detailed cards for top vulnerabilities
      vulns.slice(0, 15).forEach((vuln, i) => {
        builder.addDetailedVulnCard(vuln, i + 1);
      });

      if (vulns.length > 15) {
        builder.addText(`... and ${vulns.length - 15} more vulnerabilities`, {
          size: 8,
          color: COLORS.gray
        });
      }
    } else {
      builder.addText('No vulnerabilities detected. Target shows strong security posture.', {
        color: COLORS.gray
      });
    }

    // ===========================================
    // ATTACK MATRIX (NEW PAGE)
    // ===========================================
    builder.pdf.addPage();
    builder.pageCount++;
    builder.pdf.setFillColor(...COLORS.cream);
    builder.pdf.rect(0, 0, builder.pageWidth, builder.pageHeight, 'F');
    builder.addHeader();
    builder.addFooter();
    builder.yPos = 50;

    builder.addColoredBanner('Attack Matrix', COLORS.green, 2);

    const mitre = data.mitreTechniques || [];
    if (mitre.length > 0) {
      builder.addText(`IDENTIFIED ${mitre.length} MITRE ATT&CK TECHNIQUES`, {
        bold: true,
        size: 11,
        font: FONTS.heading
      });
      builder.addSpace(8);

      // Show technique boxes (2 per row)
      mitre.slice(0, 10).forEach((technique, i) => {
        builder.addTechniqueBox(technique, i);
      });

      // Handle odd number of techniques
      if (mitre.length % 2 === 1) {
        builder.yPos += 45;
      }

      if (mitre.length > 10) {
        builder.addText(`... and ${mitre.length - 10} more techniques`, {
          size: 8,
          color: COLORS.gray
        });
      }
    } else {
      builder.addText('No MITRE ATT&CK mappings available for this scan.', {
        color: COLORS.gray
      });
    }

    // ===========================================
    // DEFENSE PLAYBOOK (NEW PAGE)
    // ===========================================
    builder.pdf.addPage();
    builder.pageCount++;
    builder.pdf.setFillColor(...COLORS.cream);
    builder.pdf.rect(0, 0, builder.pageWidth, builder.pageHeight, 'F');
    builder.addHeader();
    builder.addFooter();
    builder.yPos = 50;

    builder.addColoredBanner('Defense Playbook', COLORS.cyan, 5);
    builder.addSpace(4);

    // Metric cards
    const riskScore = data.scanDetails.riskScore || data.riskAssessment?.overall_risk_score || 0;
    const urgentIssues = stats.critical + stats.high;
    const estimatedHours = stats.critical * 8 + stats.high * 4 + stats.medium * 2 + stats.low * 1;
    const roi = urgentIssues > 0 ? 50 : 75;

    builder.addMetricCards([
      { label: 'Risk Score', value: riskScore.toFixed(1), color: riskScore > 7 ? COLORS.coral : riskScore > 4 ? COLORS.yellow : COLORS.green },
      { label: 'Urgent Issues', value: urgentIssues, color: COLORS.yellow },
      { label: 'Est. Effort', value: `${estimatedHours}h`, color: COLORS.green },
      { label: 'ROI', value: `${roi}%`, color: COLORS.cyan }
    ]);

    // Threat distribution bar
    if (stats.total > 0) {
      builder.addText('THREAT DISTRIBUTION', { bold: true, size: 9, font: FONTS.heading });
      builder.addSpace(4);

      if (stats.critical > 0) builder.addHorizontalBar('Critical', stats.critical, stats.total, COLORS.coral);
      if (stats.high > 0) builder.addHorizontalBar('High', stats.high, stats.total, COLORS.coral);
      if (stats.medium > 0) builder.addHorizontalBar('Medium', stats.medium, stats.total, COLORS.yellow);
      if (stats.low > 0) builder.addHorizontalBar('Low', stats.low, stats.total, COLORS.cyan);
      if (stats.info > 0) builder.addHorizontalBar('Info', stats.info, stats.total, COLORS.cyan);

      builder.addSpace(8);
    }

    // Remediation timeline - use remediation strategies timeline if available
    let timelineItems = [];

    // First try to use timeline from remediation strategies
    if (data.remediationStrategies?.timeline) {
      const timeline = data.remediationStrategies.timeline;
      if (timeline.immediate_action?.items?.length > 0) {
        const items = timeline.immediate_action.items.slice(0, 2);
        items.forEach(item => {
          timelineItems.push({
            title: item.title || item.description || 'Immediate action required',
            duration: item.estimated_hours ? `${item.estimated_hours}h` : '1-2 days'
          });
        });
      }
      if (timeline.short_term?.items?.length > 0 && timelineItems.length < 3) {
        const items = timeline.short_term.items.slice(0, 1);
        items.forEach(item => {
          timelineItems.push({
            title: item.title || item.description || 'Short-term remediation',
            duration: item.estimated_hours ? `${item.estimated_hours}h` : '1 week'
          });
        });
      }
      if (timeline.long_term?.items?.length > 0 && timelineItems.length < 3) {
        const items = timeline.long_term.items.slice(0, 1);
        items.forEach(item => {
          timelineItems.push({
            title: item.title || item.description || 'Long-term improvement',
            duration: item.estimated_hours ? `${item.estimated_hours}h` : '2-4 weeks'
          });
        });
      }
    }

    // Fallback to vulnerability-based timeline
    if (timelineItems.length === 0) {
      if (stats.critical > 0) {
        timelineItems.push({ title: `Fix ${stats.critical} critical ${stats.critical === 1 ? 'vulnerability' : 'vulnerabilities'}`, duration: '24-48h' });
      }
      if (stats.high > 0 && timelineItems.length < 3) {
        timelineItems.push({ title: `Remediate ${stats.high} high severity ${stats.high === 1 ? 'issue' : 'issues'}`, duration: '1-2 weeks' });
      }
      if (stats.medium > 0 && timelineItems.length < 3) {
        timelineItems.push({ title: `Address ${stats.medium} medium priority ${stats.medium === 1 ? 'item' : 'items'}`, duration: '2-4 weeks' });
      }
    }

    if (timelineItems.length > 0) {
      builder.addTimelineTable(timelineItems.slice(0, 3));
    }

    // Cost comparison - use remediation strategies cost data if available, otherwise calculate
    let fixNow, riskExposure;

    if (data.remediationStrategies?.cost_benefit) {
      const costData = data.remediationStrategies.cost_benefit;
      fixNow = costData.fix_now_cost || costData.immediate_cost || costData.remediation_cost;
      riskExposure = costData.risk_exposure_cost || costData.potential_loss || costData.breach_cost;

      // If we have raw numbers without currency formatting
      if (fixNow && !isNaN(fixNow)) {
        fixNow = Math.round(fixNow);
      }
      if (riskExposure && !isNaN(riskExposure)) {
        riskExposure = Math.round(riskExposure);
      }
    }

    // Fallback to calculated costs based on vulnerabilities
    if (!fixNow || !riskExposure) {
      const baseCostPerVuln = { critical: 5000, high: 2000, medium: 500, low: 200, info: 50 };
      const fixNowCost = (stats.critical * baseCostPerVuln.critical) +
        (stats.high * baseCostPerVuln.high) +
        (stats.medium * baseCostPerVuln.medium) +
        (stats.low * baseCostPerVuln.low) +
        (stats.info * baseCostPerVuln.info);
      fixNow = Math.max(1000, fixNowCost);
      riskExposure = Math.round(fixNow * 1.5); // Risk is typically 50% higher than fix cost
    }

    builder.addCostComparison(fixNow, riskExposure);

    // ROI - dynamic based on risk reduction
    const calculatedROI = urgentIssues > 0
      ? Math.min(85, 40 + (urgentIssues * 5)) // Higher ROI with more urgent issues
      : (stats.total > 0 ? 50 : 75); // Base ROI depends on whether there are any findings
    builder.addROIBox(calculatedROI);

    // ACTION ITEMS Section - Dynamic based on vulnerabilities
    builder.addSpace(12);

    const actionPdf = builder.pdf;
    const actionBannerH = 12;

    // Only show action items if there are vulnerabilities
    const actionItems = [];

    if (stats.critical > 0) {
      const criticalVulns = vulns.filter(v => (v.severity || '').toLowerCase() === 'critical');
      actionItems.push({
        severity: 'CRITICAL',
        color: COLORS.coral,
        count: stats.critical,
        title: `Address ${stats.critical} Critical ${stats.critical === 1 ? 'Vulnerability' : 'Vulnerabilities'}`,
        description: `Immediate action required. Critical vulnerabilities pose severe risk and must be remediated within 24-48 hours.`,
        steps: [
          criticalVulns[0] ? `Fix: ${(criticalVulns[0].name || criticalVulns[0].title || 'Critical issue').substring(0, 100)}` : 'Review critical findings in threat catalog',
          'Implement emergency patches and security controls',
          'Verify fixes with penetration testing before deployment'
        ],
        effort: `${stats.critical * 8}-${stats.critical * 12} hours`
      });
    }

    if (stats.high > 0) {
      const highVulns = vulns.filter(v => (v.severity || '').toLowerCase() === 'high');
      actionItems.push({
        severity: 'HIGH',
        color: COLORS.coral,
        count: stats.high,
        title: `Remediate ${stats.high} High Severity ${stats.high === 1 ? 'Issue' : 'Issues'}`,
        description: `High priority vulnerabilities require prompt attention. Schedule remediation within 1-2 weeks.`,
        steps: [
          highVulns[0] ? `Prioritize: ${(highVulns[0].name || highVulns[0].title || 'High severity issue').substring(0, 100)}` : 'Review high severity findings',
          'Develop and test security patches',
          'Deploy fixes during next maintenance window'
        ],
        effort: `${stats.high * 4}-${stats.high * 6} hours`
      });
    }

    if (stats.medium > 0) {
      actionItems.push({
        severity: 'MEDIUM',
        color: COLORS.yellow,
        count: stats.medium,
        title: `Address ${stats.medium} Medium Risk ${stats.medium === 1 ? 'Finding' : 'Findings'}`,
        description: `Medium severity issues should be addressed within 30 days as part of regular security maintenance.`,
        steps: [
          'Review medium severity vulnerabilities and assess business impact',
          'Schedule remediation in upcoming sprint or release cycle',
          'Implement security hardening measures'
        ],
        effort: `${stats.medium * 2}-${stats.medium * 3} hours`
      });
    }

    if (stats.info > 0) {
      actionItems.push({
        severity: 'INFO',
        color: COLORS.cyan,
        count: stats.info,
        title: `Review ${stats.info} Info Severity ${stats.info === 1 ? 'Item' : 'Items'}`,
        description: `Informational findings provide security insights and best practice recommendations.`,
        steps: [
          'Review informational findings for security improvements',
          'Assess potential security impact in your environment',
          'Implement recommended security controls and configurations'
        ],
        effort: `${Math.max(1, stats.info)}-${Math.max(2, stats.info * 2)} hours`
      });
    }

    // If no vulnerabilities, show general security review
    if (actionItems.length === 0) {
      actionItems.push({
        severity: 'REVIEW',
        color: COLORS.green,
        count: 0,
        title: 'Conduct Security Review',
        description: `No vulnerabilities detected. Continue monitoring and maintaining security posture.`,
        steps: [
          'Review current security configurations and controls',
          'Verify all security best practices are implemented',
          'Schedule regular security scans and assessments'
        ],
        effort: '2-4 hours'
      });
    }

    actionItems.forEach((item, itemIdx) => {
      builder.checkAddPage(75);

      // Coral banner for ACTION ITEMS
      actionPdf.setFillColor(...COLORS.coral);
      actionPdf.setDrawColor(...COLORS.black);
      actionPdf.setLineWidth(1.5);
      actionPdf.rect(builder.margin, builder.yPos, builder.contentWidth, actionBannerH, 'FD');

      // Black corner on banner
      actionPdf.setFillColor(...COLORS.black);
      actionPdf.rect(builder.margin + builder.contentWidth - 5, builder.yPos, 5, 5, 'F');

      // Page number box
      const pageNumBoxSize = 10;
      const pageNumX = builder.margin + builder.contentWidth - pageNumBoxSize - 8;
      actionPdf.setFillColor(...COLORS.white);
      actionPdf.setDrawColor(...COLORS.black);
      actionPdf.setLineWidth(1);
      actionPdf.rect(pageNumX, builder.yPos + 1, pageNumBoxSize, pageNumBoxSize, 'FD');
      actionPdf.setFont(FONTS.heading, 'bold');
      actionPdf.setFontSize(9);
      actionPdf.setTextColor(...COLORS.black);
      actionPdf.text(String(itemIdx + 1), pageNumX + pageNumBoxSize / 2, builder.yPos + 7.5, { align: 'center' });

      // Banner text
      actionPdf.setFont(FONTS.heading, 'bold');
      actionPdf.setFontSize(11);
      actionPdf.text('ACTION ITEMS', builder.margin + 5, builder.yPos + 8);

      builder.yPos += actionBannerH + 8;

      const actionCardH = 65;

      // Shadow
      actionPdf.setFillColor(200, 200, 200);
      actionPdf.rect(builder.margin + 2, builder.yPos + 2, builder.contentWidth, actionCardH, 'F');

      // White card
      actionPdf.setFillColor(...COLORS.white);
      actionPdf.setDrawColor(...COLORS.black);
      actionPdf.setLineWidth(1.5);
      actionPdf.rect(builder.margin, builder.yPos, builder.contentWidth, actionCardH, 'FD');

      // Black corners
      actionPdf.setFillColor(...COLORS.black);
      actionPdf.rect(builder.margin, builder.yPos, 5, 5, 'F');
      actionPdf.rect(builder.margin + builder.contentWidth - 5, builder.yPos, 5, 5, 'F');

      // Number badge
      const numBadgeSize = 8;
      actionPdf.setFillColor(...COLORS.white);
      actionPdf.setDrawColor(...COLORS.black);
      actionPdf.setLineWidth(1);
      actionPdf.rect(builder.margin + 5, builder.yPos + 5, numBadgeSize, numBadgeSize, 'FD');
      actionPdf.setFont(FONTS.heading, 'bold');
      actionPdf.setFontSize(8);
      actionPdf.text(String(itemIdx + 1), builder.margin + 5 + numBadgeSize / 2, builder.yPos + 10.5, { align: 'center' });

      // Severity badge
      const sevBadgeW = item.severity.length * 3.5 + 6;
      const sevBadgeH = 7;
      const sevBadgeX = builder.margin + 18;
      actionPdf.setFillColor(...item.color);
      actionPdf.rect(sevBadgeX, builder.yPos + 6, sevBadgeW, sevBadgeH, 'FD');
      actionPdf.setFont(FONTS.heading, 'bold');
      actionPdf.setFontSize(6);
      actionPdf.setTextColor(...COLORS.black);
      actionPdf.text(item.severity, sevBadgeX + sevBadgeW / 2, builder.yPos + 10.5, { align: 'center' });

      // Title
      actionPdf.setFont(FONTS.body, 'bold');
      actionPdf.setFontSize(9);
      actionPdf.text(item.title, builder.margin + 18 + sevBadgeW + 5, builder.yPos + 11);

      // Tag on right
      const tagW = 60;
      const tagH = 6;
      const tagX = builder.margin + builder.contentWidth - tagW - 5;
      actionPdf.setFillColor(240, 240, 240);
      actionPdf.setDrawColor(180, 180, 180);
      actionPdf.setLineWidth(0.5);
      actionPdf.rect(tagX, builder.yPos + 6, tagW, tagH, 'FD');
      actionPdf.setFont(FONTS.body, 'normal');
      actionPdf.setFontSize(6);
      actionPdf.setTextColor(100, 100, 100);
      actionPdf.text('VULNERABILITY REMEDIATION', tagX + tagW / 2, builder.yPos + 9.5, { align: 'center' });

      // Description
      actionPdf.setFont(FONTS.body, 'normal');
      actionPdf.setFontSize(8);
      actionPdf.setTextColor(...COLORS.darkText);
      const descLines = actionPdf.splitTextToSize(item.description, builder.contentWidth - 14);
      descLines.slice(0, 2).forEach((line, lineIdx) => {
        actionPdf.text(line, builder.margin + 7, builder.yPos + 20 + (lineIdx * 4));
      });

      // STEPS section
      actionPdf.setFont(FONTS.body, 'bold');
      actionPdf.setFontSize(7);
      actionPdf.setTextColor(...COLORS.black);
      actionPdf.text('STEPS:', builder.margin + 7, builder.yPos + 30);

      actionPdf.setFont(FONTS.body, 'normal');
      actionPdf.setFontSize(7);

      let stepY = builder.yPos + 36;
      item.steps.forEach((step, i) => {
        const stepLines = actionPdf.splitTextToSize(`${i + 1}. ${step}`, builder.contentWidth - 20);
        stepLines.forEach((line, lineIdx) => {
          if (stepY < builder.yPos + actionCardH - 8) {
            actionPdf.text(line, builder.margin + 7, stepY);
            stepY += 4;
          }
        });
      });

      // Effort
      actionPdf.setFont(FONTS.body, 'bold');
      actionPdf.setFontSize(7);
      actionPdf.text('Effort:', builder.margin + 7, builder.yPos + actionCardH - 5);
      actionPdf.setFont(FONTS.body, 'normal');
      actionPdf.text(item.effort, builder.margin + 20, builder.yPos + actionCardH - 5);

      builder.yPos += actionCardH + 10;
    });

    // Recommendations with pink checkboxes and yellow badges
    builder.addSpace(6);

    // Cyan info box
    const infoBoxH = 12;
    pdf.setFillColor(...COLORS.cyan);
    pdf.setDrawColor(...COLORS.black);
    pdf.setLineWidth(1);
    pdf.rect(builder.margin, builder.yPos, builder.contentWidth, infoBoxH, 'FD');

    pdf.setFontSize(8);
    pdf.setFont(FONTS.body, 'normal');
    pdf.setTextColor(...COLORS.black);
    pdf.text('Insights align with the timeline above. Each recommendation updates as new scan data arrives.', builder.margin + 5, builder.yPos + 8);

    builder.yPos += infoBoxH + 8;

    builder.addText('EXPERT INSIGHTS & RECOMMENDATIONS', { bold: true, size: 10, font: FONTS.heading });
    builder.addSpace(6);

    // Get dynamic recommendations from scan data with multiple fallbacks
    const remediationRecs = data.remediationStrategies?.recommendations || [];
    const directRecs = data.recommendations || [];
    const scanRecommendations = remediationRecs.length > 0 ? remediationRecs : directRecs;

    const displayRecommendations = scanRecommendations.length > 0
      ? scanRecommendations.slice(0, 5).map(rec => {
        if (typeof rec === 'string') return rec;
        return rec.title || rec.recommendation || rec.description || 'Security Recommendation';
      })
      : (vulns.length > 0
        ? vulns.slice(0, 5).map(v => `Address: ${(v.name || v.title || 'Security Issue').substring(0, 70)}`)
        : ['Review and harden security configuration', 'Implement security monitoring and logging', 'Enable web application firewall (WAF)', 'Conduct regular security assessments', 'Update security documentation']);

    displayRecommendations.forEach(rec => {
      builder.checkAddPage(25);

      // Card with shadow
      const cardH = 20;
      pdf.setFillColor(200, 200, 200);
      pdf.rect(builder.margin + 2, builder.yPos + 2, builder.contentWidth - 50, cardH, 'F');

      // White card
      pdf.setFillColor(...COLORS.white);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(1.5);
      pdf.rect(builder.margin, builder.yPos, builder.contentWidth - 50, cardH, 'FD');

      // Pink checkbox
      const checkSize = 4;
      pdf.setFillColor(...COLORS.pink);
      pdf.rect(builder.margin - checkSize - 2, builder.yPos + 2, checkSize, checkSize, 'F');

      // Text
      pdf.setFontSize(9);
      pdf.setFont(FONTS.heading, 'bold');
      pdf.setTextColor(...COLORS.black);
      pdf.text(rec.toUpperCase(), builder.margin + 5, builder.yPos + 12);

      // Yellow badge (L for Low priority)
      const badgeSize = 8;
      const badgeX = builder.margin + builder.contentWidth - 55;

      pdf.setFillColor(180, 180, 180);
      pdf.rect(badgeX + 1, builder.yPos + 7, badgeSize, badgeSize, 'F');

      pdf.setFillColor(...COLORS.yellow);
      pdf.setDrawColor(...COLORS.black);
      pdf.setLineWidth(1);
      pdf.rect(badgeX, builder.yPos + 6, badgeSize, badgeSize, 'FD');

      pdf.setFontSize(6);
      pdf.setFont(FONTS.heading, 'bold');
      pdf.text('L', badgeX + badgeSize / 2, builder.yPos + 11.5, { align: 'center' });

      builder.yPos += cardH + 5;
    });

    // ===========================================
    // INTEL ANALYSIS (NEW PAGE)
    // ===========================================
    builder.pdf.addPage();
    builder.pageCount++;
    builder.pdf.setFillColor(...COLORS.cream);
    builder.pdf.rect(0, 0, builder.pageWidth, builder.pageHeight, 'F');
    builder.addHeader();
    builder.addFooter();
    builder.yPos = 50;

    builder.addColoredBanner('Intel Analysis', COLORS.blue, 6);

    const intel = data.realtimeIntel || [];
    if (intel.length > 0) {
      builder.addText('REAL-TIME THREAT INTELLIGENCE', {
        bold: true,
        size: 10,
        font: FONTS.heading
      });
      builder.addSpace(6);

      const intelPdf = builder.pdf;

      intel.slice(0, 8).forEach((item, i) => {
        builder.checkAddPage(20);

        const itemH = 16;

        // Shadow
        intelPdf.setFillColor(200, 200, 200);
        intelPdf.rect(builder.margin + 1.5, builder.yPos + 1.5, builder.contentWidth, itemH, 'F');

        // White card
        intelPdf.setFillColor(...COLORS.white);
        intelPdf.setDrawColor(...COLORS.black);
        intelPdf.setLineWidth(1.5);
        intelPdf.rect(builder.margin, builder.yPos, builder.contentWidth, itemH, 'FD');

        // Black corner
        intelPdf.setFillColor(...COLORS.black);
        intelPdf.rect(builder.margin + builder.contentWidth - 4, builder.yPos, 4, 4, 'F');

        // Source badge
        const sourceBadgeW = 45;
        const sourceBadgeH = 7;
        intelPdf.setFillColor(...COLORS.blue);
        intelPdf.setDrawColor(...COLORS.black);
        intelPdf.setLineWidth(1);
        intelPdf.rect(builder.margin + 4, builder.yPos + 4, sourceBadgeW, sourceBadgeH, 'FD');
        intelPdf.setFont(FONTS.heading, 'bold');
        intelPdf.setFontSize(6);
        intelPdf.setTextColor(...COLORS.white);
        const sourceName = String(item.source || 'THREAT INTEL').toUpperCase().substring(0, 15);
        intelPdf.text(sourceName, builder.margin + 4 + sourceBadgeW / 2, builder.yPos + 8.5, { align: 'center' });

        // Description
        intelPdf.setFont(FONTS.body, 'normal');
        intelPdf.setFontSize(8);
        intelPdf.setTextColor(...COLORS.black);
        const desc = String(item.description || item.title || item.indicator || 'Threat indicator detected');
        const descLines = intelPdf.splitTextToSize(desc, builder.contentWidth - 12);
        descLines.slice(0, 2).forEach((line, lineIdx) => {
          intelPdf.text(line, builder.margin + 4, builder.yPos + 12 + (lineIdx * 4));
        });

        builder.yPos += itemH + 4;
      });

      if (intel.length > 8) {
        builder.addText(`... and ${intel.length - 8} more threat intelligence sources`, {
          size: 7,
          color: COLORS.gray
        });
        builder.addSpace(4);
      }
    } else {
      builder.addText('No real-time threat intelligence data available for this scan.', {
        color: COLORS.gray
      });
    }

    // NEXT STEPS section with yellow banner
    builder.addSpace(12);

    const nextPdf = builder.pdf;
    const nextBannerH = 12;

    // Yellow banner for NEXT STEPS
    nextPdf.setFillColor(...COLORS.yellow);
    nextPdf.setDrawColor(...COLORS.black);
    nextPdf.setLineWidth(1.5);
    nextPdf.rect(builder.margin, builder.yPos, builder.contentWidth, nextBannerH, 'FD');

    // Black corner
    nextPdf.setFillColor(...COLORS.black);
    nextPdf.rect(builder.margin + builder.contentWidth - 5, builder.yPos, 5, 5, 'F');

    nextPdf.setFont(FONTS.heading, 'bold');
    nextPdf.setFontSize(11);
    nextPdf.setTextColor(...COLORS.black);
    nextPdf.text('NEXT STEPS', builder.margin + 5, builder.yPos + 8);

    builder.yPos += nextBannerH + 10;

    const nextSteps = [
      { num: '1', text: 'Review all findings and prioritize based on severity and business impact.' },
      { num: '2', text: 'Assign remediation tasks to appropriate development and security teams.' },
      { num: '3', text: 'Implement fixes for critical and high severity vulnerabilities within 72 hours.' },
      { num: '4', text: 'Deploy security patches to production environments after thorough testing.' },
      { num: '5', text: 'Update security documentation, runbooks, and incident response procedures.' },
      { num: '6', text: 'Schedule follow-up scan after all fixes are implemented to verify resolution.' },
      { num: '7', text: 'Conduct team training on identified vulnerability patterns and secure coding practices.' },
      { num: '8', text: 'Enable continuous monitoring and automated scanning for ongoing security assessment.' }
    ];

    const stepCardH = 22;
    const stepCardW = (builder.contentWidth - 10) / 3;
    const stepColGap = 5;
    const stepRowGap = 6;

    let currentRow = 0;
    let startYPos = builder.yPos;

    nextSteps.forEach((step, i) => {
      const col = i % 3;
      const row = Math.floor(i / 3);

      // Start new row
      if (row !== currentRow) {
        currentRow = row;
        startYPos = builder.yPos;
      }

      builder.checkAddPage(stepCardH + 8);

      const stepX = builder.margin + (col * (stepCardW + stepColGap));
      const stepY = startYPos;

      // Shadow
      nextPdf.setFillColor(200, 200, 200);
      nextPdf.rect(stepX + 1.5, stepY + 1.5, stepCardW, stepCardH, 'F');

      // Yellow card
      nextPdf.setFillColor(...COLORS.yellow);
      nextPdf.setDrawColor(...COLORS.black);
      nextPdf.setLineWidth(1.5);
      nextPdf.rect(stepX, stepY, stepCardW, stepCardH, 'FD');

      // Black corner
      nextPdf.setFillColor(...COLORS.black);
      nextPdf.rect(stepX + stepCardW - 3.5, stepY, 3.5, 3.5, 'F');

      // Number box
      const numSize = 8;
      nextPdf.setFillColor(...COLORS.white);
      nextPdf.setDrawColor(...COLORS.black);
      nextPdf.setLineWidth(1);
      nextPdf.rect(stepX + 4, stepY + 4, numSize, numSize, 'FD');
      nextPdf.setFont(FONTS.heading, 'bold');
      nextPdf.setFontSize(7);
      nextPdf.setTextColor(...COLORS.black);
      nextPdf.text(step.num, stepX + 4 + numSize / 2, stepY + 9, { align: 'center' });

      // Text
      nextPdf.setFont(FONTS.body, 'normal');
      nextPdf.setFontSize(7);
      const stepLines = nextPdf.splitTextToSize(step.text, stepCardW - 10);
      stepLines.slice(0, 4).forEach((line, lineIdx) => {
        nextPdf.text(line, stepX + 4, stepY + 15 + (lineIdx * 3.5));
      });

      // Move Y position after completing a row
      if (col === 2 || i === nextSteps.length - 1) {
        builder.yPos = stepY + stepCardH + stepRowGap;
      }
    });

    builder.yPos += 6;

    // Finalize
    const pdfDoc = builder.finalize();
    const filename = `LinkLoad_Security_Report_${scanId}_${new Date().toISOString().split('T')[0]}.pdf`;
    pdfDoc.save(filename);

    console.log('[PDF] Generation complete:', filename);
    return { success: true, filename };

  } catch (error) {
    console.error('[PDF] Generation failed:', error);
    return { success: false, error: error.message };
  }
};
