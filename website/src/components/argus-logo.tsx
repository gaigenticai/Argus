"use client";

import { useEffect, useId, useState } from "react";

export function ArgusLogo({ size = 44 }: { size?: number }) {
  const uid = useId().replace(/:/g, "");
  const [blink, setBlink] = useState(false);

  useEffect(() => {
    let timeout: ReturnType<typeof setTimeout>;
    const scheduleBlink = () => {
      // Slow, deliberate blink every 6-10 seconds
      const delay = 6000 + Math.random() * 4000;
      timeout = setTimeout(() => {
        setBlink(true);
        setTimeout(() => {
          setBlink(false);
          scheduleBlink();
        }, 200);
      }, delay);
    };
    scheduleBlink();
    return () => clearTimeout(timeout);
  }, []);

  return (
    <div style={{ width: size, height: size, flexShrink: 0, position: "relative" }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 64 64"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* ── Background — dark aged canvas ── */}
        <rect x="0" y="0" width="64" height="64" rx="14" fill={`url(#${uid}bg)`} />

        {/* Warm inner glow like candlelit painting */}
        <rect x="2" y="2" width="60" height="60" rx="12" fill={`url(#${uid}inner)`} opacity="0.12" />

        {/* ── Upper skin area (forehead/brow) ── */}
        <path
          d="M8 30C8 22 16 14 32 14C48 14 56 22 56 30"
          fill={`url(#${uid}skinup)`}
          opacity="0.25"
        />

        {/* ── Sclera (white of the eye) ── */}
        <ellipse
          cx="32" cy="32" rx="19" ry="11"
          fill={`url(#${uid}sclera)`}
          style={{
            transition: "ry 0.18s ease-in-out",
            ry: blink ? 0.3 : 11,
          } as React.CSSProperties}
        />

        {/* Sclera shadow at top (from upper lid) */}
        <ellipse
          cx="32" cy="27" rx="16" ry="4"
          fill="#8B7355"
          opacity={blink ? 0 : 0.12}
          style={{ transition: "opacity 0.15s" }}
        />

        {/* ── Blood vessels / veins for realism ── */}
        <g opacity={blink ? 0 : 0.18} style={{ transition: "opacity 0.12s" }}>
          <path d="M14 30Q18 28 22 30Q20 29 18 30" stroke="#C4574A" strokeWidth="0.35" fill="none" />
          <path d="M15 33Q19 32 21 33" stroke="#C4574A" strokeWidth="0.25" fill="none" />
          <path d="M42 30Q46 28 50 30Q48 29 46 30" stroke="#C4574A" strokeWidth="0.35" fill="none" />
          <path d="M43 33Q47 32 49 33" stroke="#C4574A" strokeWidth="0.25" fill="none" />
          <path d="M16 29Q17 27 20 28" stroke="#B5443A" strokeWidth="0.2" fill="none" />
          <path d="M44 29Q45 27 48 28" stroke="#B5443A" strokeWidth="0.2" fill="none" />
        </g>

        {/* ── Iris — layered for depth ── */}
        {/* Outer iris ring */}
        <circle
          cx="32" cy="32" r="9"
          fill={`url(#${uid}irisOuter)`}
          style={{ transition: "opacity 0.12s", opacity: blink ? 0 : 1 }}
        />
        {/* Inner iris detail */}
        <circle
          cx="32" cy="32" r="7"
          fill={`url(#${uid}irisInner)`}
          style={{ transition: "opacity 0.12s", opacity: blink ? 0 : 1 }}
        />
        {/* Iris fibres (radial lines) */}
        <g opacity={blink ? 0 : 0.15} style={{ transition: "opacity 0.12s" }}>
          {[0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330].map((angle) => {
            const rad = (angle * Math.PI) / 180;
            const x1 = 32 + Math.cos(rad) * 4;
            const y1 = 32 + Math.sin(rad) * 4;
            const x2 = 32 + Math.cos(rad) * 8;
            const y2 = 32 + Math.sin(rad) * 8;
            return (
              <line
                key={angle}
                x1={x1} y1={y1} x2={x2} y2={y2}
                stroke="#3D2510"
                strokeWidth="0.3"
              />
            );
          })}
        </g>

        {/* Limbal ring (dark ring around iris) */}
        <circle
          cx="32" cy="32" r="9"
          stroke="#1A0E05"
          strokeWidth="0.7"
          fill="none"
          opacity={blink ? 0 : 0.5}
          style={{ transition: "opacity 0.12s" }}
        />

        {/* ── Pupil ── */}
        <circle
          cx="32" cy="32" r="3.5"
          fill="#050505"
          style={{ transition: "opacity 0.12s", opacity: blink ? 0 : 1 }}
        />

        {/* Catchlight reflections — 2 points like studio lighting */}
        <ellipse
          cx="29" cy="29.5" rx="1.8" ry="1.4"
          fill="white"
          opacity={blink ? 0 : 0.9}
          style={{ transition: "opacity 0.12s" }}
        />
        <circle
          cx="35" cy="34" r="0.7"
          fill="white"
          opacity={blink ? 0 : 0.45}
          style={{ transition: "opacity 0.12s" }}
        />

        {/* ── Upper eyelid crease (double fold) ── */}
        <path
          d="M10 28C10 28 18 16 32 16C46 16 54 28 54 28"
          stroke={`url(#${uid}crease)`}
          strokeWidth="0.8"
          strokeLinecap="round"
          fill="none"
          opacity="0.4"
        />

        {/* ── Upper eyelid edge ── */}
        <path
          d="M12 32C12 32 18 21 32 21C46 21 52 32 52 32"
          stroke={`url(#${uid}lidEdge)`}
          strokeWidth="2"
          strokeLinecap="round"
          fill="none"
        />

        {/* Upper lash line — thicker at center */}
        <path
          d="M13 32C13 32 19 21.5 32 21.5C45 21.5 51 32 51 32"
          stroke="#1A0E05"
          strokeWidth="0.8"
          strokeLinecap="round"
          fill="none"
          opacity="0.6"
        />

        {/* ── Lower eyelid edge ── */}
        <path
          d="M14 32C14 32 20 42 32 42C44 42 50 32 50 32"
          stroke={`url(#${uid}lidLo)`}
          strokeWidth="1.2"
          strokeLinecap="round"
          fill="none"
          opacity="0.5"
        />

        {/* ── Closing eyelid (blink) ── */}
        <ellipse
          cx="32" cy="32" rx="20" ry={blink ? 12 : 0}
          fill={`url(#${uid}skinBlink)`}
          style={{
            transition: "ry 0.18s ease-in-out",
          } as React.CSSProperties}
        />
        {blink && (
          <path
            d="M12 32C12 32 20 33 32 33C44 33 52 32 52 32"
            stroke="#3D2B1F"
            strokeWidth="1.5"
            strokeLinecap="round"
            fill="none"
          />
        )}

        {/* ── Tear duct & outer corner ── */}
        <ellipse cx="13" cy="32" rx="1" ry="0.7" fill="#D4A886" opacity="0.4" />
        <ellipse cx="51" cy="32" rx="0.8" ry="0.5" fill="#C49A7A" opacity="0.3" />

        {/* ── Argus teal glow — subtle brand signature under eye ── */}
        <path
          d="M18 44Q32 48 46 44"
          stroke="#00A76F"
          strokeWidth="1.2"
          strokeLinecap="round"
          fill="none"
          opacity="0.5"
        />

        <defs>
          <linearGradient id={`${uid}bg`} x1="0" y1="0" x2="64" y2="64">
            <stop offset="0%" stopColor="#1C1612" />
            <stop offset="40%" stopColor="#231C16" />
            <stop offset="100%" stopColor="#161210" />
          </linearGradient>

          <radialGradient id={`${uid}inner`} cx="0.5" cy="0.45" r="0.55">
            <stop offset="0%" stopColor="#D4A876" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>

          <linearGradient id={`${uid}skinup`} x1="32" y1="14" x2="32" y2="30">
            <stop offset="0%" stopColor="#8B7355" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>

          <radialGradient id={`${uid}sclera`} cx="0.48" cy="0.45" r="0.5">
            <stop offset="0%" stopColor="#F7F0E8" />
            <stop offset="60%" stopColor="#EDE4D8" />
            <stop offset="100%" stopColor="#D4C4B0" />
          </radialGradient>

          <radialGradient id={`${uid}irisOuter`} cx="0.45" cy="0.42" r="0.55">
            <stop offset="0%" stopColor="#C49A30" />
            <stop offset="40%" stopColor="#8B6914" />
            <stop offset="70%" stopColor="#5B3A1A" />
            <stop offset="100%" stopColor="#2A1A0A" />
          </radialGradient>

          <radialGradient id={`${uid}irisInner`} cx="0.42" cy="0.4" r="0.6">
            <stop offset="0%" stopColor="#D4AA40" stopOpacity="0.6" />
            <stop offset="50%" stopColor="#7A5518" stopOpacity="0.4" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>

          <linearGradient id={`${uid}crease`} x1="10" y1="20" x2="54" y2="20">
            <stop offset="0%" stopColor="#6B5540" />
            <stop offset="50%" stopColor="#8B7355" />
            <stop offset="100%" stopColor="#6B5540" />
          </linearGradient>

          <linearGradient id={`${uid}lidEdge`} x1="12" y1="26" x2="52" y2="26">
            <stop offset="0%" stopColor="#6B5540" />
            <stop offset="50%" stopColor="#9A836A" />
            <stop offset="100%" stopColor="#6B5540" />
          </linearGradient>

          <linearGradient id={`${uid}lidLo`} x1="14" y1="38" x2="50" y2="38">
            <stop offset="0%" stopColor="#7A6550" />
            <stop offset="50%" stopColor="#9A836A" />
            <stop offset="100%" stopColor="#7A6550" />
          </linearGradient>

          <radialGradient id={`${uid}skinBlink`} cx="0.5" cy="0.5" r="0.5">
            <stop offset="0%" stopColor="#A0896E" />
            <stop offset="100%" stopColor="#8B7355" />
          </radialGradient>
        </defs>
      </svg>
    </div>
  );
}
