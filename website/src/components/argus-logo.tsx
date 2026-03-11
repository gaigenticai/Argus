"use client";

import { useEffect, useId, useState } from "react";

export function ArgusLogo({ size = 36 }: { size?: number }) {
  const uid = useId().replace(/:/g, "");
  const [blink, setBlink] = useState(false);

  useEffect(() => {
    // Blink every 4-7 seconds (natural, not robotic)
    let timeout: ReturnType<typeof setTimeout>;
    const scheduleBlink = () => {
      const delay = 4000 + Math.random() * 3000;
      timeout = setTimeout(() => {
        setBlink(true);
        // Eyelid stays closed for 150ms
        setTimeout(() => {
          setBlink(false);
          scheduleBlink();
        }, 150);
      }, delay);
    };
    scheduleBlink();
    return () => clearTimeout(timeout);
  }, []);

  // Scale factor so the viewBox art maps to any size
  const s = size / 48;

  return (
    <div style={{ width: size, height: size, flexShrink: 0, position: "relative" }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 48 48"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* ── Background ── */}
        <rect x="0" y="0" width="48" height="48" rx="12" fill={`url(#${uid}bg)`} />

        {/* Warm parchment inner glow */}
        <rect x="3" y="3" width="42" height="42" rx="9" fill={`url(#${uid}inner)`} opacity="0.15" />

        {/* ── Sclera (white of the eye) with warm Renaissance tint ── */}
        <ellipse
          cx="24" cy="24" rx="14" ry="9"
          fill={`url(#${uid}sclera)`}
          style={{
            transition: "ry 0.12s ease-in-out",
            ry: blink ? 0.5 : 9,
          } as React.CSSProperties}
        />

        {/* ── Iris — rich amber/gold like old master paintings ── */}
        <circle
          cx="24" cy="24" r="7"
          fill={`url(#${uid}iris)`}
          style={{
            transition: "opacity 0.1s",
            opacity: blink ? 0 : 1,
          }}
        />

        {/* Iris detail ring */}
        <circle
          cx="24" cy="24" r="5.5"
          stroke="#5B3A1A"
          strokeWidth="0.4"
          fill="none"
          opacity={blink ? 0 : 0.3}
          style={{ transition: "opacity 0.1s" }}
        />

        {/* ── Pupil — deep black ── */}
        <circle
          cx="24" cy="24" r="3"
          fill="#0A0A0A"
          style={{
            transition: "opacity 0.1s",
            opacity: blink ? 0 : 1,
          }}
        />

        {/* Pupil light reflection — gives it life */}
        <circle
          cx="22" cy="22.5" r="1.2"
          fill="white"
          opacity={blink ? 0 : 0.85}
          style={{ transition: "opacity 0.1s" }}
        />
        <circle
          cx="25.5" cy="25" r="0.5"
          fill="white"
          opacity={blink ? 0 : 0.5}
          style={{ transition: "opacity 0.1s" }}
        />

        {/* ── Upper eyelid — the skin fold with shadow ── */}
        <path
          d="M7 24C7 24 13 13 24 13C35 13 41 24 41 24"
          stroke={`url(#${uid}lid)`}
          strokeWidth="2.5"
          strokeLinecap="round"
          fill="none"
        />

        {/* ── Lower eyelid — softer ── */}
        <path
          d="M9 24C9 24 14 33 24 33C34 33 39 24 39 24"
          stroke={`url(#${uid}lidlo)`}
          strokeWidth="1.5"
          strokeLinecap="round"
          fill="none"
          opacity="0.6"
        />

        {/* ── Closing eyelid (blink overlay) ── */}
        <ellipse
          cx="24" cy="24" rx="15" ry={blink ? 10 : 0}
          fill={`url(#${uid}skin)`}
          style={{
            transition: "ry 0.12s ease-in-out",
          } as React.CSSProperties}
        />

        {/* ── Subtle lash line on blink ── */}
        {blink && (
          <line
            x1="9" y1="24" x2="39" y2="24"
            stroke="#3D2B1F"
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        )}

        {/* ── Corner details (tear duct / outer corner) ── */}
        <circle cx="9" cy="24" r="0.8" fill="#C4956A" opacity="0.5" />
        <circle cx="39" cy="24" r="0.6" fill="#C4956A" opacity="0.4" />

        {/* ── Subtle vein lines for realism ── */}
        <path d="M10 22Q13 21 16 22" stroke="#D4725E" strokeWidth="0.3" fill="none" opacity="0.2" />
        <path d="M32 22Q35 21 38 22" stroke="#D4725E" strokeWidth="0.3" fill="none" opacity="0.15" />

        {/* ── Teal accent glow under the eye — the "Argus" signature ── */}
        <path
          d="M14 34Q24 37 34 34"
          stroke="#00A76F"
          strokeWidth="1"
          strokeLinecap="round"
          fill="none"
          opacity="0.7"
        />

        <defs>
          {/* Dark background — aged canvas / fresco feel */}
          <linearGradient id={`${uid}bg`} x1="0" y1="0" x2="48" y2="48">
            <stop offset="0%" stopColor="#1A1410" />
            <stop offset="50%" stopColor="#201A14" />
            <stop offset="100%" stopColor="#15110D" />
          </linearGradient>

          {/* Warm inner glow */}
          <radialGradient id={`${uid}inner`} cx="0.5" cy="0.5" r="0.6">
            <stop offset="0%" stopColor="#C4956A" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>

          {/* Sclera — warm white, not pure white */}
          <radialGradient id={`${uid}sclera`} cx="0.5" cy="0.5" r="0.5">
            <stop offset="0%" stopColor="#F5EDE4" />
            <stop offset="70%" stopColor="#E8DDD2" />
            <stop offset="100%" stopColor="#D4C4B0" />
          </radialGradient>

          {/* Iris — deep amber/hazel with teal tint (Argus brand) */}
          <radialGradient id={`${uid}iris`} cx="0.45" cy="0.45" r="0.55">
            <stop offset="0%" stopColor="#B8860B" />
            <stop offset="35%" stopColor="#8B6914" />
            <stop offset="65%" stopColor="#5B3A1A" />
            <stop offset="85%" stopColor="#2D5A3D" />
            <stop offset="100%" stopColor="#1A3D2B" />
          </radialGradient>

          {/* Eyelid skin tones */}
          <linearGradient id={`${uid}lid`} x1="7" y1="13" x2="41" y2="13">
            <stop offset="0%" stopColor="#8B7355" />
            <stop offset="50%" stopColor="#A0896E" />
            <stop offset="100%" stopColor="#8B7355" />
          </linearGradient>

          <linearGradient id={`${uid}lidlo`} x1="9" y1="33" x2="39" y2="33">
            <stop offset="0%" stopColor="#7A6550" />
            <stop offset="50%" stopColor="#9A836A" />
            <stop offset="100%" stopColor="#7A6550" />
          </linearGradient>

          {/* Blink overlay skin */}
          <radialGradient id={`${uid}skin`} cx="0.5" cy="0.5" r="0.5">
            <stop offset="0%" stopColor="#A0896E" />
            <stop offset="100%" stopColor="#8B7355" />
          </radialGradient>
        </defs>
      </svg>
    </div>
  );
}
