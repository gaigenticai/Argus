"use client";

export function ArgusLogo({ size = 36, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={{ flexShrink: 0 }}
    >
      {/* Outer ring — the panoptic boundary */}
      <circle cx="24" cy="24" r="22" stroke="url(#argus-ring)" strokeWidth="2.5" fill="none" />

      {/* Inner eye shape — two arcs forming an almond */}
      <path
        d="M6 24C6 24 13 12 24 12C35 12 42 24 42 24C42 24 35 36 24 36C13 36 6 24 6 24Z"
        stroke="url(#argus-eye)" strokeWidth="2" fill="none" strokeLinejoin="round"
      />

      {/* Iris ring */}
      <circle cx="24" cy="24" r="7.5" stroke="url(#argus-iris)" strokeWidth="2" fill="none" />

      {/* Pupil — the core */}
      <circle cx="24" cy="24" r="3" fill="url(#argus-pupil)" />

      {/* Scan lines — digital surveillance aesthetic */}
      <line x1="24" y1="2" x2="24" y2="10" stroke="url(#argus-scan)" strokeWidth="1.5" strokeLinecap="round" opacity="0.6" />
      <line x1="24" y1="38" x2="24" y2="46" stroke="url(#argus-scan)" strokeWidth="1.5" strokeLinecap="round" opacity="0.6" />
      <line x1="2" y1="24" x2="10" y2="24" stroke="url(#argus-scan)" strokeWidth="1.5" strokeLinecap="round" opacity="0.4" />
      <line x1="38" y1="24" x2="46" y2="24" stroke="url(#argus-scan)" strokeWidth="1.5" strokeLinecap="round" opacity="0.4" />

      <defs>
        <linearGradient id="argus-ring" x1="2" y1="2" x2="46" y2="46">
          <stop offset="0%" stopColor="#00A76F" />
          <stop offset="100%" stopColor="#8E33FF" />
        </linearGradient>
        <linearGradient id="argus-eye" x1="6" y1="24" x2="42" y2="24">
          <stop offset="0%" stopColor="#00A76F" stopOpacity="0.8" />
          <stop offset="50%" stopColor="#FFFFFF" />
          <stop offset="100%" stopColor="#8E33FF" stopOpacity="0.8" />
        </linearGradient>
        <linearGradient id="argus-iris" x1="16.5" y1="16.5" x2="31.5" y2="31.5">
          <stop offset="0%" stopColor="#00A76F" />
          <stop offset="100%" stopColor="#00D68F" />
        </linearGradient>
        <radialGradient id="argus-pupil" cx="24" cy="24" r="3">
          <stop offset="0%" stopColor="#FFFFFF" />
          <stop offset="60%" stopColor="#00A76F" />
          <stop offset="100%" stopColor="#005B3A" />
        </radialGradient>
        <linearGradient id="argus-scan" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#00A76F" />
          <stop offset="100%" stopColor="#00A76F" stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  );
}
