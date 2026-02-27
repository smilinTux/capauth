#!/usr/bin/env node
/**
 * Generate CapAuth extension icons as PNG files.
 *
 * Uses an SVG template rendered to Canvas via Node.js.
 * Requires: npm install canvas (dev dependency, only for icon generation).
 *
 * Alternatively, convert the SVG manually with Inkscape:
 *   inkscape --export-type=png --export-width=16 icon.svg -o icons/icon16.png
 *   inkscape --export-type=png --export-width=48 icon.svg -o icons/icon48.png
 *   inkscape --export-type=png --export-width=128 icon.svg -o icons/icon128.png
 *
 * The SVG source is saved to icons/icon.svg for manual conversion.
 */

const fs = require("fs");
const path = require("path");

// CapAuth shield icon SVG — purple shield with cyan checkmark
const SVG_TEMPLATE = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <defs>
    <linearGradient id="shieldFill" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#7C3AED"/>
      <stop offset="100%" stop-color="#5b21b6"/>
    </linearGradient>
    <linearGradient id="shieldStroke" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#a78bfa"/>
      <stop offset="100%" stop-color="#7C3AED"/>
    </linearGradient>
  </defs>
  <!-- Background circle -->
  <circle cx="64" cy="64" r="60" fill="#0f0f1a"/>
  <circle cx="64" cy="64" r="58" fill="none" stroke="url(#shieldStroke)" stroke-width="2" opacity="0.4"/>
  <!-- Shield -->
  <path d="M64 18L28 38v28c0 24.4 16.9 47.3 36 52.8 19.1-5.5 36-28.4 36-52.8V38L64 18z"
        fill="url(#shieldFill)" opacity="0.35"/>
  <path d="M64 18L28 38v28c0 24.4 16.9 47.3 36 52.8 19.1-5.5 36-28.4 36-52.8V38L64 18z"
        stroke="url(#shieldStroke)" stroke-width="4" fill="none"/>
  <!-- Checkmark -->
  <path d="M48 64l12 12 20-20" stroke="#00e5ff" stroke-width="8"
        stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>`;

const iconsDir = path.join(__dirname, "..", "icons");

// Ensure icons directory exists
if (!fs.existsSync(iconsDir)) {
  fs.mkdirSync(iconsDir, { recursive: true });
}

// Save SVG source for manual conversion
const svgPath = path.join(iconsDir, "icon.svg");
fs.writeFileSync(svgPath, SVG_TEMPLATE);
console.log(`Saved ${svgPath}`);

// Try to generate PNGs using Inkscape or rsvg-convert if available
const { execSync } = require("child_process");

const sizes = [16, 48, 128];

// Try Inkscape first
let converter = null;
try {
  execSync("inkscape --version", { stdio: "pipe" });
  converter = "inkscape";
} catch {
  // Try rsvg-convert
  try {
    execSync("rsvg-convert --version", { stdio: "pipe" });
    converter = "rsvg";
  } catch {
    // Try ImageMagick convert
    try {
      execSync("magick --version", { stdio: "pipe" });
      converter = "magick";
    } catch {
      console.log("");
      console.log("No SVG-to-PNG converter found.");
      console.log("Install one of: inkscape, librsvg, imagemagick");
      console.log("Or convert icons/icon.svg manually to:");
      for (const size of sizes) {
        console.log(`  icons/icon${size}.png (${size}x${size})`);
      }
      process.exit(0);
    }
  }
}

for (const size of sizes) {
  const outPath = path.join(iconsDir, `icon${size}.png`);
  try {
    if (converter === "inkscape") {
      execSync(`inkscape --export-type=png --export-width=${size} --export-height=${size} "${svgPath}" -o "${outPath}"`, { stdio: "pipe" });
    } else if (converter === "rsvg") {
      execSync(`rsvg-convert -w ${size} -h ${size} "${svgPath}" -o "${outPath}"`, { stdio: "pipe" });
    } else if (converter === "magick") {
      execSync(`magick -background none -resize ${size}x${size} "${svgPath}" "${outPath}"`, { stdio: "pipe" });
    }
    console.log(`Generated ${outPath} (${size}x${size})`);
  } catch (err) {
    console.error(`Failed to generate icon${size}.png: ${err.message}`);
  }
}
