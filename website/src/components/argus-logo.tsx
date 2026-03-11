"use client";

export function ArgusLogo({ size = 36 }: { size?: number }) {
  // Unique IDs to avoid conflicts when multiple logos render
  const id = `al${size}`;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      style={{ flexShrink: 0 }}
    >
      {/* Background — rounded square with gradient */}
      <rect
        x="1" y="1" width="46" height="46" rx="13"
        fill={`url(#${id}-bg)`}
      />

      {/* Eye shape — bold filled almond */}
      <path
        d="M8 24C8 24 14.5 14 24 14C33.5 14 40 24 40 24C40 24 33.5 34 24 34C14.5 34 8 24 8 24Z"
        fill={`url(#${id}-eye)`}
        opacity="0.25"
      />
      <path
        d="M8 24C8 24 14.5 14 24 14C33.5 14 40 24 40 24C40 24 33.5 34 24 34C14.5 34 8 24 8 24Z"
        stroke="white"
        strokeWidth="1.8"
        strokeLinejoin="round"
        fill="none"
        opacity="0.9"
      />

      {/* Iris — solid ring */}
      <circle cx="24" cy="24" r="6.5" fill={`url(#${id}-iris)`} />

      {/* Pupil — bright center dot */}
      <circle cx="24" cy="24" r="2.5" fill="white" />

      {/* Top accent notch — the "vigilance" mark */}
      <path
        d="M24 4L27 9H21L24 4Z"
        fill={`url(#${id}-notch)`}
        opacity="0.8"
      />

      <defs>
        <linearGradient id={`${id}-bg`} x1="0" y1="0" x2="48" y2="48">
          <stop offset="0%" stopColor="#00A76F" />
          <stop offset="60%" stopColor="#007B55" />
          <stop offset="100%" stopColor="#005B3A" />
        </linearGradient>
        <linearGradient id={`${id}-eye`} x1="8" y1="24" x2="40" y2="24">
          <stop offset="0%" stopColor="#00FFB2" />
          <stop offset="100%" stopColor="#FFFFFF" />
        </linearGradient>
        <radialGradient id={`${id}-iris`} cx="0.5" cy="0.5" r="0.5">
          <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.9" />
          <stop offset="40%" stopColor="#00FFB2" />
          <stop offset="100%" stopColor="#00A76F" />
        </radialGradient>
        <linearGradient id={`${id}-notch`} x1="24" y1="4" x2="24" y2="9">
          <stop offset="0%" stopColor="#00FFB2" />
          <stop offset="100%" stopColor="#00A76F" />
        </linearGradient>
      </defs>
    </svg>
  );
}
