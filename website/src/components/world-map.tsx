"use client";

import { useEffect, useRef, useCallback } from "react";

interface ThreatDot {
  x: number;
  y: number;
  size: number;
  opacity: number;
  color: string;
  pulseSpeed: number;
  pulsePhase: number;
  pingTimer: number;
  pingInterval: number;
}

interface ConnectionLine {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  progress: number;
  speed: number;
  color: string;
  opacity: number;
}

// Simplified world map paths — continents as SVG-friendly coordinate arrays
// Normalized to 0-1000 x 0-500 coordinate space
const CONTINENT_PATHS: number[][][] = [
  // North America
  [[150,80],[200,70],[250,75],[290,90],[310,100],[320,130],[310,160],[280,180],[250,200],[220,210],[180,220],[140,210],[120,200],[100,180],[90,150],[95,120],[110,100],[130,90],[150,80]],
  // South America
  [[230,230],[250,225],[270,240],[280,270],[285,310],[280,340],[270,370],[260,390],[240,400],[225,395],[210,370],[205,340],[210,310],[215,280],[220,250],[230,230]],
  // Europe
  [[430,70],[460,60],[490,65],[510,75],[520,90],[525,110],[520,130],[510,140],[490,145],[470,140],[450,135],[440,120],[430,105],[425,90],[430,70]],
  // Africa
  [[440,155],[470,150],[500,155],[520,170],[530,200],[535,240],[530,280],[520,310],[500,330],[480,340],[460,335],[445,320],[435,290],[430,260],[432,230],[435,200],[438,170],[440,155]],
  // Asia
  [[530,55],[570,45],[620,40],[670,50],[720,55],[760,65],[790,80],[800,100],[790,120],[770,140],[740,155],[700,165],[660,170],[620,165],[580,155],[550,140],[535,120],[530,100],[528,80],[530,55]],
  // Russia/Northern Asia
  [[510,30],[550,20],[600,15],[660,18],[720,22],[770,30],[810,40],[830,55],[820,70],[790,75],[760,60],[710,50],[660,45],[600,35],[550,30],[510,30]],
  // Australia
  [[740,280],[770,275],[800,280],[820,290],[830,310],[825,330],[810,345],[790,350],[770,345],[755,335],[745,315],[740,295],[740,280]],
  // Southeast Asia islands
  [[720,170],[740,168],[755,175],[760,190],[755,200],[740,205],[725,200],[720,188],[720,170]],
  // Japan
  [[800,85],[810,82],[815,90],[812,100],[805,105],[798,100],[795,92],[800,85]],
  // UK
  [[430,55],[438,50],[445,55],[443,65],[436,68],[430,63],[430,55]],
];

// Major city positions for threat dots (normalized 0-1000 x 0-500)
const HOTSPOTS: [number, number][] = [
  [180, 130], // New York
  [140, 145], // Chicago
  [90, 160],  // LA
  [160, 160], // Miami
  [120, 110], // Toronto
  [240, 290], // São Paulo
  [250, 270], // Bogotá
  [450, 95],  // London
  [470, 95],  // Paris
  [490, 85],  // Berlin
  [510, 105], // Rome
  [530, 80],  // Moscow
  [600, 110], // Tehran
  [640, 120], // Mumbai
  [680, 100], // Delhi
  [720, 130], // Bangkok
  [750, 120], // Hong Kong
  [770, 100], // Shanghai
  [800, 90],  // Tokyo
  [790, 110], // Seoul
  [780, 300], // Sydney
  [460, 200], // Lagos
  [490, 250], // Nairobi
  [500, 170], // Cairo
  [455, 75],  // Amsterdam
  [540, 65],  // St. Petersburg
  [650, 135], // Bangalore
  [200, 100], // Washington DC
  [70, 130],  // San Francisco
  [160, 90],  // Montreal
];

const COLORS = {
  red: "#FF5630",
  orange: "#FFAB00",
  teal: "#00A76F",
  purple: "#8E33FF",
  cyan: "#00BBD9",
};

export function WorldMap() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const dotsRef = useRef<ThreatDot[]>([]);
  const linesRef = useRef<ConnectionLine[]>([]);
  const timeRef = useRef(0);

  const initDots = useCallback((w: number, h: number) => {
    const scaleX = w / 1000;
    const scaleY = h / 500;
    const colorKeys = Object.keys(COLORS) as (keyof typeof COLORS)[];

    dotsRef.current = HOTSPOTS.map(([hx, hy]) => ({
      x: hx * scaleX + (Math.random() - 0.5) * 20 * scaleX,
      y: hy * scaleY + (Math.random() - 0.5) * 20 * scaleY,
      size: 2 + Math.random() * 3,
      opacity: 0.4 + Math.random() * 0.6,
      color: COLORS[colorKeys[Math.floor(Math.random() * colorKeys.length)]],
      pulseSpeed: 0.5 + Math.random() * 2,
      pulsePhase: Math.random() * Math.PI * 2,
      pingTimer: 0,
      pingInterval: 3000 + Math.random() * 8000,
    }));

    // Add extra random dots on continents
    for (let i = 0; i < 40; i++) {
      dotsRef.current.push({
        x: (50 + Math.random() * 900) * scaleX,
        y: (30 + Math.random() * 380) * scaleY,
        size: 1 + Math.random() * 2,
        opacity: 0.2 + Math.random() * 0.4,
        color: COLORS[colorKeys[Math.floor(Math.random() * colorKeys.length)]],
        pulseSpeed: 0.3 + Math.random() * 1.5,
        pulsePhase: Math.random() * Math.PI * 2,
        pingTimer: 0,
        pingInterval: 5000 + Math.random() * 12000,
      });
    }
  }, []);

  const initLines = useCallback((w: number, h: number) => {
    const scaleX = w / 1000;
    const scaleY = h / 500;
    const colorKeys = Object.keys(COLORS) as (keyof typeof COLORS)[];

    const connections: [number, number][] = [
      [0, 4], [0, 6], [1, 5], [2, 28], [4, 7], [7, 8], [8, 9],
      [9, 11], [11, 12], [12, 13], [14, 15], [15, 16], [16, 17],
      [17, 18], [18, 19], [20, 16], [21, 23], [22, 13], [6, 21],
      [3, 7], [27, 0], [24, 8], [25, 11], [26, 14], [28, 17],
    ];

    linesRef.current = connections.map(([a, b]) => ({
      x1: HOTSPOTS[a][0] * scaleX,
      y1: HOTSPOTS[a][1] * scaleY,
      x2: HOTSPOTS[b][0] * scaleX,
      y2: HOTSPOTS[b][1] * scaleY,
      progress: Math.random(),
      speed: 0.0003 + Math.random() * 0.0005,
      color: COLORS[colorKeys[Math.floor(Math.random() * colorKeys.length)]],
      opacity: 0.08 + Math.random() * 0.12,
    }));
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      const ctx = canvas.getContext("2d");
      if (ctx) ctx.scale(dpr, dpr);
      initDots(rect.width, rect.height);
      initLines(rect.width, rect.height);
    };

    resize();
    window.addEventListener("resize", resize);

    const draw = (timestamp: number) => {
      const dt = timestamp - timeRef.current;
      timeRef.current = timestamp;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const w = canvas.getBoundingClientRect().width;
      const h = canvas.getBoundingClientRect().height;
      const scaleX = w / 1000;
      const scaleY = h / 500;

      ctx.clearRect(0, 0, w, h);

      // Draw continent outlines
      ctx.strokeStyle = "rgba(0, 167, 111, 0.08)";
      ctx.lineWidth = 1;
      ctx.fillStyle = "rgba(0, 167, 111, 0.02)";

      for (const path of CONTINENT_PATHS) {
        ctx.beginPath();
        for (let i = 0; i < path.length; i++) {
          const px = path[i][0] * scaleX;
          const py = path[i][1] * scaleY;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      }

      // Draw grid lines
      ctx.strokeStyle = "rgba(0, 167, 111, 0.025)";
      ctx.lineWidth = 0.5;
      for (let lat = 0; lat < 500; lat += 50) {
        ctx.beginPath();
        ctx.moveTo(0, lat * scaleY);
        ctx.lineTo(w, lat * scaleY);
        ctx.stroke();
      }
      for (let lng = 0; lng < 1000; lng += 50) {
        ctx.beginPath();
        ctx.moveTo(lng * scaleX, 0);
        ctx.lineTo(lng * scaleX, h);
        ctx.stroke();
      }

      // Draw connection lines
      for (const line of linesRef.current) {
        line.progress = (line.progress + line.speed * dt) % 1;

        // Static line
        ctx.beginPath();
        ctx.strokeStyle = line.color;
        ctx.globalAlpha = line.opacity;
        ctx.lineWidth = 0.8;
        ctx.moveTo(line.x1, line.y1);

        // Curved line
        const mx = (line.x1 + line.x2) / 2;
        const my = Math.min(line.y1, line.y2) - Math.abs(line.x2 - line.x1) * 0.15;
        ctx.quadraticCurveTo(mx, my, line.x2, line.y2);
        ctx.stroke();

        // Traveling dot
        const t = line.progress;
        const tx = (1 - t) * (1 - t) * line.x1 + 2 * (1 - t) * t * mx + t * t * line.x2;
        const ty = (1 - t) * (1 - t) * line.y1 + 2 * (1 - t) * t * my + t * t * line.y2;

        ctx.beginPath();
        ctx.globalAlpha = 0.8;
        ctx.fillStyle = line.color;
        ctx.arc(tx, ty, 1.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      // Draw threat dots
      const now = timestamp;
      for (const dot of dotsRef.current) {
        const pulse = Math.sin(now * 0.001 * dot.pulseSpeed + dot.pulsePhase);
        const currentSize = dot.size + pulse * 1.2;
        const currentOpacity = dot.opacity * (0.6 + pulse * 0.4);

        // Ping ring
        dot.pingTimer += dt;
        if (dot.pingTimer > dot.pingInterval) {
          dot.pingTimer = 0;
        }
        const pingProgress = dot.pingTimer / dot.pingInterval;
        if (pingProgress < 0.3) {
          const ringSize = currentSize + pingProgress * 30;
          const ringAlpha = 0.3 * (1 - pingProgress / 0.3);
          ctx.beginPath();
          ctx.strokeStyle = dot.color;
          ctx.globalAlpha = ringAlpha;
          ctx.lineWidth = 1;
          ctx.arc(dot.x, dot.y, ringSize, 0, Math.PI * 2);
          ctx.stroke();
        }

        // Outer glow
        ctx.beginPath();
        ctx.globalAlpha = currentOpacity * 0.3;
        ctx.fillStyle = dot.color;
        ctx.arc(dot.x, dot.y, currentSize * 3, 0, Math.PI * 2);
        ctx.fill();

        // Core dot
        ctx.beginPath();
        ctx.globalAlpha = currentOpacity;
        ctx.fillStyle = dot.color;
        ctx.arc(dot.x, dot.y, currentSize, 0, Math.PI * 2);
        ctx.fill();

        ctx.globalAlpha = 1;
      }

      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animRef.current);
    };
  }, [initDots, initLines]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
      }}
    />
  );
}
