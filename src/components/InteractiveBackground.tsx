'use client';

import { useEffect, useRef } from 'react';

interface Node {
  x: number;
  y: number;
  vx: number;
  vy: number;
  depth: number; // 0.4-1 — closer nodes (higher depth) are bigger/brighter/faster, selling parallax depth
}

const LINK_DISTANCE = 150;
const MOUSE_LINK_DISTANCE = 220;
const NODE_DENSITY = 1 / 16000; // nodes per px^2
const MAX_NODES = 85;

/**
 * A quiet, ambient "security mesh" — nodes drifting slowly and linking when
 * close, plus a soft pull toward the cursor. Depth (not just darkness) comes
 * from three layers moving at different speeds: canvas nodes, and two
 * blurred gradient orbs behind them (see .scene-orb in globals.css).
 *
 * Fully static (one paint, no rAF loop) when prefers-reduced-motion is set.
 */
export default function InteractiveBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let width = 0;
    let height = 0;
    let dpr = Math.min(window.devicePixelRatio || 1, 2);
    let nodes: Node[] = [];
    const mouse = { x: -9999, y: -9999, active: false };

    function resize() {
      const canvas = canvasRef.current;
      if (!canvas) return;
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);

      const count = Math.min(MAX_NODES, Math.round(width * height * NODE_DENSITY));
      nodes = Array.from({ length: count }, () => {
        const depth = 0.4 + Math.random() * 0.6;
        return {
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 0.15 * depth,
          vy: (Math.random() - 0.5) * 0.15 * depth,
          depth,
        };
      });
    }

    function onPointerMove(e: PointerEvent) {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      mouse.active = true;
    }
    function onPointerLeave() {
      mouse.active = false;
    }

    resize();
    window.addEventListener('resize', resize);
    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('pointerleave', onPointerLeave);

    function drawFrame() {
      ctx!.clearRect(0, 0, width, height);

      for (const n of nodes) {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < 0 || n.x > width) n.vx *= -1;
        if (n.y < 0 || n.y > height) n.vy *= -1;

        if (mouse.active) {
          const dx = mouse.x - n.x;
          const dy = mouse.y - n.y;
          const dist = Math.hypot(dx, dy);
          if (dist < 260 && dist > 1) {
            const pull = ((260 - dist) / 260) * 0.02;
            n.vx += (dx / dist) * pull;
            n.vy += (dy / dist) * pull;
          }
        }
        const speedCap = 0.4 * n.depth;
        n.vx = Math.max(-speedCap, Math.min(speedCap, n.vx));
        n.vy = Math.max(-speedCap, Math.min(speedCap, n.vy));
      }

      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i];
          const b = nodes[j];
          const dist = Math.hypot(a.x - b.x, a.y - b.y);
          if (dist < LINK_DISTANCE) {
            const alpha = (1 - dist / LINK_DISTANCE) * 0.16 * ((a.depth + b.depth) / 2);
            ctx!.strokeStyle = `rgba(148, 152, 255, ${alpha})`;
            ctx!.lineWidth = 1;
            ctx!.beginPath();
            ctx!.moveTo(a.x, a.y);
            ctx!.lineTo(b.x, b.y);
            ctx!.stroke();
          }
        }
        if (mouse.active) {
          const dist = Math.hypot(mouse.x - nodes[i].x, mouse.y - nodes[i].y);
          if (dist < MOUSE_LINK_DISTANCE) {
            const alpha = (1 - dist / MOUSE_LINK_DISTANCE) * 0.32;
            ctx!.strokeStyle = `rgba(124, 108, 240, ${alpha})`;
            ctx!.lineWidth = 1;
            ctx!.beginPath();
            ctx!.moveTo(mouse.x, mouse.y);
            ctx!.lineTo(nodes[i].x, nodes[i].y);
            ctx!.stroke();
          }
        }
      }

      for (const n of nodes) {
        const r = 1 + n.depth * 1.4;
        ctx!.beginPath();
        ctx!.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(200, 202, 255, ${0.25 + n.depth * 0.35})`;
        ctx!.fill();
      }
    }

    if (reduceMotion) {
      drawFrame();
      return () => {
        window.removeEventListener('resize', resize);
        window.removeEventListener('pointermove', onPointerMove);
        window.removeEventListener('pointerleave', onPointerLeave);
      };
    }

    let raf = 0;
    function loop() {
      drawFrame();
      raf = requestAnimationFrame(loop);
    }
    raf = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('pointerleave', onPointerLeave);
    };
  }, []);

  return (
    <div className="scene-backdrop" aria-hidden="true">
      <div className="scene-orb o1" />
      <div className="scene-orb o2" />
      <div className="scene-orb o3" />
      <canvas ref={canvasRef} />
    </div>
  );
}
