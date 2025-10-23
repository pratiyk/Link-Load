# Design System Developer Guide

## 👨‍💻 For Developers Maintaining Link&Load UI

This guide explains how to work with and maintain the minimalist design system built on golden ratio proportions.

---

## 🎯 Core Concepts

### Golden Ratio in Code

The golden ratio (φ ≈ 1.618) is the foundation of all spacing and sizing:

```javascript
const φ = 1.618;
const baseUnit = 1; // rem

// Spacing values
const spacing = {
  0: 1 / (φ * φ),           // 0.382rem (tight)
  1: 1 / φ,                 // 0.618rem (compact)
  2: 1,                     // 1rem (normal)
  3: φ,                     // 1.618rem (relaxed)
  4: φ * φ,                 // 2.618rem (generous)
  5: φ * φ * φ,             // 4.236rem (expansive)
};

// Font sizes
const fontSizes = {
  md: 1,
  lg: φ,
  xl: φ * φ,
  '2xl': φ * φ * φ,
  '3xl': φ * φ * φ * φ,
};
```

---

## 🛠️ Working with CSS Variables

### Access System Variables

All styling uses CSS variables. They're defined in `index.css`:

```css
/* Example: Using spacing */
.card {
  padding: var(--spacing-4);    /* Always reference variables */
}

/* Example: Using typography */
h2 {
  font-family: var(--font-serif);
  font-size: var(--font-size-2xl);
  line-height: 1.618;
}

/* Example: Using colors */
.element {
  color: var(--color-black);
  background: var(--color-white);
  border: 1px solid var(--color-gray-medium);
}
```

### Variable Naming Convention

```
--[category]-[level/variant]

Categories:
- color-*        (colors)
- font-*         (typography)
- spacing-*      (spacing)
- shadow-*       (shadows)
- radius-*       (border radius)

Examples:
- --color-black
- --color-gray-medium
- --font-size-lg
- --spacing-4
- --shadow-md
- --radius-lg
```

---

## 📐 When to Use Each Spacing

### --spacing-0 (0.382rem)
**Use for:** Small vertical adjustments, micro-spacing
```css
.label {
  margin-bottom: var(--spacing-0);
}
```

### --spacing-1 (0.618rem)
**Use for:** Compact spacing between related elements
```css
.icon-with-label {
  gap: var(--spacing-1);
}
```

### --spacing-2 (1rem)
**Use for:** Normal padding/margins, standard gaps
```css
.input {
  padding: var(--spacing-2);
}

.grid {
  gap: var(--spacing-2);
}
```

### --spacing-3 (1.618rem)
**Use for:** Relaxed spacing, medium margins
```css
.card {
  margin-bottom: var(--spacing-3);
}

.section-content {
  gap: var(--spacing-3);
}
```

### --spacing-4 (2.618rem)
**Use for:** Generous padding in cards/containers
```css
.card {
  padding: var(--spacing-4);
}

.menu {
  gap: var(--spacing-4);
}
```

### --spacing-5 (4.236rem)
**Use for:** Large section margins, expansive spacing
```css
.section {
  padding: var(--spacing-5) var(--spacing-4);
}

.heading {
  margin-bottom: var(--spacing-5);
}
```

---

## 📝 Typography Guidelines

### Font Family Usage

**Cormorant Garamond (Serif)** - For headings:
```css
h1, h2, h3, h4, h5, h6 {
  font-family: var(--font-serif);
}

.title {
  font-family: var(--font-serif);
}
```

**Syne (Sans-serif)** - For body and UI:
```css
body, p, a, button, input {
  font-family: var(--font-sans);
}
```

**Courier Prime (Monospace)** - For code/terminal:
```css
.code, .terminal, .monospace {
  font-family: 'Courier Prime', monospace;
}
```

### Font Size Selection

| Component | Size | Usage |
|-----------|------|-------|
| Page title | --font-size-3xl (6.854rem) | Hero/main heading |
| Section title | --font-size-2xl (4.236rem) | Section headings |
| Card title | --font-size-lg (1.618rem) | Feature card titles |
| Body text | --font-size-md (1rem) | Paragraphs |
| Small text | --font-size-sm (0.875rem) | Metadata, descriptions |
| Tiny text | --font-size-xs (0.75rem) | Labels, badges |

### Line Height

All text uses `line-height: 1.618` (golden ratio):

```css
p, a, span, h1, h2, h3, h4, h5, h6 {
  line-height: 1.618;
}
```

---

## 🎨 Color System Usage

### Semantic Color Usage

```css
/* Primary emphasis - important text, primary buttons */
.important {
  color: var(--color-black);
}

/* Secondary text - descriptions, hints */
.secondary {
  color: var(--color-gray-dark);
}

/* Borders and dividers */
.divider {
  border-color: var(--color-gray-medium);
}

/* Light backgrounds */
.light-bg {
  background: var(--color-gray-light);
}

/* Main background */
.page {
  background: var(--color-white);
}

/* Functional states */
.error { color: var(--color-error); }
.success { color: var(--color-success); }
.warning { color: var(--color-warning); }
.info { color: var(--color-info); }
```

### Creating Color Variations

Don't hardcode colors. Use semantic CSS classes:

```css
/* ❌ DON'T */
.card {
  background: #fafaf9;
}

/* ✅ DO */
.card {
  background: var(--color-white);
}
```

---

## 🎬 Animation Best Practices

### Standard Transitions

All interactive elements use 0.3s ease:

```css
.element {
  transition: all 0.3s ease;
}

/* For specific properties */
.element {
  transition: color 0.3s ease, 
              border-color 0.3s ease,
              box-shadow 0.3s ease;
}
```

### Hover Effects Pattern

```css
.card {
  border: 1px solid var(--color-gray-medium);
  transition: all 0.3s ease;
}

.card:hover {
  border-color: var(--color-black);
  box-shadow: var(--shadow-md);
  transform: translateY(-2px);
}
```

### Avoid

❌ Animations longer than 0.5s (feels sluggish)
❌ Multiple simultaneous animations (chaotic)
❌ Easing functions other than `ease` or `ease-in-out` (jarring)
❌ Animations on page load (disorienting)

---

## 📐 Creating New Components

### Step 1: Plan Structure

```jsx
<div className="component">
  <div className="component-header">
    <h3>Title</h3>
  </div>
  <div className="component-body">
    {/* Content */}
  </div>
  <div className="component-footer">
    <button>Action</button>
  </div>
</div>
```

### Step 2: Write CSS Using Variables

```css
.component {
  background: var(--color-white);
  border: 1px solid var(--color-gray-medium);
  border-radius: var(--radius-md);
  padding: var(--spacing-4);
  display: flex;
  flex-direction: column;
  gap: var(--spacing-2);
  transition: all 0.3s ease;
}

.component-header {
  border-bottom: 1px solid var(--color-gray-light);
  padding-bottom: var(--spacing-2);
  margin-bottom: var(--spacing-2);
}

.component-header h3 {
  font-family: var(--font-serif);
  font-size: var(--font-size-lg);
  margin: 0;
}

.component-body {
  flex: 1;
  color: var(--color-gray-dark);
  font-size: var(--font-size-sm);
}

.component-footer {
  border-top: 1px solid var(--color-gray-light);
  padding-top: var(--spacing-2);
  margin-top: var(--spacing-2);
}

.component:hover {
  border-color: var(--color-black);
  box-shadow: var(--shadow-md);
}
```

### Step 3: Test Responsive

```css
@media (max-width: 768px) {
  .component {
    padding: calc(var(--spacing-4) * 0.8);
  }
  
  .component-header h3 {
    font-size: var(--font-size-md);
  }
}

@media (max-width: 480px) {
  .component {
    padding: calc(var(--spacing-4) * 0.6);
    gap: var(--spacing-1);
  }
}
```

---

## ✅ Code Review Checklist

When reviewing CSS/design changes:

- [ ] Uses CSS variables (not hardcoded values)
- [ ] Follows golden ratio spacing
- [ ] Typography hierarchy is clear
- [ ] Color usage is semantic
- [ ] Transitions are 0.3s ease
- [ ] Hover states are subtle
- [ ] Mobile responsive tested
- [ ] Accessibility considered
- [ ] No layout shifts on hover
- [ ] Performance optimized

---

## 🔍 Debugging Tips

### Problem: Inconsistent Spacing

**Solution:** Always use variables
```css
/* ❌ Inconsistent */
.card {
  padding: 1.5rem;  /* Different from --spacing-4: 2.618rem */
}

/* ✅ Consistent */
.card {
  padding: var(--spacing-4);
}
```

### Problem: Typography Looks Wrong

**Solution:** Check line-height and letter-spacing
```css
h2 {
  font-family: var(--font-serif);
  font-size: var(--font-size-2xl);
  line-height: 1.618;          /* Must have */
  letter-spacing: -0.02em;     /* Serif adjustment */
}
```

### Problem: Mobile Looks Cramped

**Solution:** Scale proportionally
```css
@media (max-width: 768px) {
  :root {
    --base-unit: 0.8rem;  /* Reduces all sizes */
  }
  
  /* Or adjust individual components */
  .card {
    padding: calc(var(--spacing-4) * 0.8);
  }
}
```

### Problem: Hover Animation Jerky

**Solution:** Use GPU acceleration
```css
.element {
  transition: all 0.3s ease;
  /* Use transform, not top/left/width/height */
}

.element:hover {
  transform: translateY(-2px);  /* GPU accelerated */
  /* NOT: top: -2px; */
}
```

---

## 🚀 Performance Optimizations

### CSS Optimization Tips

```css
/* ✅ Good - Uses variables */
.button {
  padding: var(--spacing-2);
  color: var(--color-black);
}

/* ❌ Avoid - Hardcoded values */
.button {
  padding: 1rem;
  color: #1a1a1a;
}

/* ✅ Good - GPU accelerated */
.element:hover {
  transform: translateY(-2px);
}

/* ❌ Avoid - CPU rendered */
.element:hover {
  top: -2px;
  position: relative;
}

/* ✅ Good - Efficient selector */
.card { }
.card-header { }

/* ❌ Avoid - Deep nesting */
.container .card .inner .header { }
```

---

## 📚 File Organization

```
frontend/src/
├── index.css
│   ├── CSS variables (all options)
│   ├── Global styles
│   ├── Base elements (body, h1-h6, p, a)
│   ├── Forms (inputs, buttons, labels)
│   ├── Utilities (loading, animations)
│   └── Responsive base
│
├── styles/
│   ├── home.css (page-specific)
│   ├── ScanResults.css
│   ├── components.css (shared components)
│   └── utilities.css (helper classes)
│
├── components/ (React components)
│   ├── Card.jsx
│   ├── Button.jsx
│   └── ...
│
└── pages/ (Page components)
    ├── Home.jsx
    ├── ScanResults.jsx
    └── ...
```

---

## 🔄 Updating the Design System

### Changing Spacing Values

**Modify:** `index.css` `:root` variables
**Impact:** All components update automatically
**Example:**
```css
:root {
  --ratio: 1.618;
  --spacing-4: calc(var(--base-unit) * var(--ratio) * var(--ratio));
}
```

### Changing Colors

**Modify:** `index.css` color variables
**Impact:** All color usages update
**Example:**
```css
:root {
  --color-black: #2a2a2a;
  --color-white: #f0f0ee;
}
```

### Changing Fonts

**Modify:** `index.css` font variables
**Impact:** Typography everywhere updates
**Example:**
```css
@import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&display=swap');

:root {
  --font-serif: 'Playfair Display', serif;
}
```

---

## 🧪 Testing Checklist

### Visual Testing
- [ ] Desktop view (1440px) - full design
- [ ] Tablet view (768px) - scaled layout
- [ ] Mobile view (375px) - single column
- [ ] Ultra-mobile (320px) - minimal layout

### Interaction Testing
- [ ] Hover states work smoothly
- [ ] Focus states visible for accessibility
- [ ] Animations perform at 60fps
- [ ] No layout shifts on interactions

### Browser Testing
- [ ] Chrome (latest)
- [ ] Firefox (latest)
- [ ] Safari (latest)
- [ ] Edge (latest)

### Accessibility Testing
- [ ] Color contrast ratio ≥ 4.5:1
- [ ] Keyboard navigation works
- [ ] Screen reader compatible
- [ ] Focus visible on all interactive elements

---

## 📖 Common Tasks

### Add New Color

```css
/* In index.css :root */
:root {
  --color-new: #abc123;
}

/* Usage in component */
.element {
  color: var(--color-new);
}
```

### Adjust Section Padding

```css
.section {
  /* Current: generous spacing */
  padding: var(--spacing-5) var(--spacing-4);
  
  /* More compact */
  padding: var(--spacing-4) var(--spacing-3);
  
  /* Very compact */
  padding: var(--spacing-3) var(--spacing-2);
}
```

### Create Responsive Typography

```css
.title {
  font-size: var(--font-size-2xl);
  line-height: 1.618;
}

@media (max-width: 768px) {
  .title {
    font-size: var(--font-size-xl);
  }
}

@media (max-width: 480px) {
  .title {
    font-size: var(--font-size-lg);
  }
}
```

### Add Hover Animation

```css
.element {
  transition: all 0.3s ease;
  cursor: pointer;
}

.element:hover {
  color: var(--color-black);
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}
```

---

## 💡 Best Practices

### ✅ DO

1. **Use variables consistently** - Never hardcode values
2. **Follow naming conventions** - Clear, semantic names
3. **Test responsively** - Check all breakpoints
4. **Comment complex code** - Explain unusual patterns
5. **Minimize animations** - Keep it refined
6. **Use semantic HTML** - Proper element types
7. **Test accessibility** - Keyboard and screen readers

### ❌ DON'T

1. **Hardcode colors/spacing** - Use variables always
2. **Create custom spacing** - Stick to system values
3. **Animate on page load** - Feels jarring
4. **Use multiple transitions** - Causes animation chaos
5. **Ignore responsive design** - Test all sizes
6. **Add unnecessary decorations** - Keep it minimal
7. **Break accessibility** - Colors, contrast, focus

---

## 🆘 Getting Help

### Troubleshooting Guide

1. **Check CSS variables are loaded** - Open DevTools
2. **Verify selector specificity** - Not being overridden
3. **Test in different browsers** - Cross-browser issue?
4. **Check responsive breakpoints** - Mobile breakpoint?
5. **Review documentation** - DESIGN_SYSTEM.md
6. **Inspect similar components** - Pattern matching

### Documentation Files

- **DESIGN_SYSTEM.md** - Complete specifications
- **GOLDEN_RATIO_GUIDE.md** - Ratio details
- **QUICK_REFERENCE.md** - Quick lookup
- **UI_UPDATE_SUMMARY.md** - Update history
- **DEVELOPER_GUIDE.md** - This file

---

## 📞 Questions?

Refer to:
1. DESIGN_SYSTEM.md for specs
2. Code comments in CSS files
3. Component examples in existing code
4. CSS variables in index.css

---

**Last Updated:** October 23, 2025  
**Version:** 2.0.0  
**Status:** Production Ready  
**Maintainer:** Design System Team
