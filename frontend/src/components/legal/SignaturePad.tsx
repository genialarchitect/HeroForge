import React, { useRef, useEffect, useState, useCallback, forwardRef, useImperativeHandle } from 'react';

export interface SignaturePadRef {
  clear: () => void;
  isEmpty: () => boolean;
  toDataURL: (type?: string) => string;
}

interface SignaturePadProps {
  width?: number;
  height?: number;
  penColor?: string;
  penWidth?: number;
  backgroundColor?: string;
  onChange?: (isEmpty: boolean) => void;
  className?: string;
}

const SignaturePad = forwardRef<SignaturePadRef, SignaturePadProps>(
  (
    {
      width = 500,
      height = 200,
      penColor = '#000000',
      penWidth = 2,
      backgroundColor = '#ffffff',
      onChange,
      className = '',
    },
    ref
  ) => {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const [isDrawing, setIsDrawing] = useState(false);
    const [isEmpty, setIsEmpty] = useState(true);
    const lastPoint = useRef<{ x: number; y: number } | null>(null);

    // Initialize canvas
    useEffect(() => {
      const canvas = canvasRef.current;
      if (!canvas) return;

      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      // Set canvas resolution for high DPI displays
      const dpr = window.devicePixelRatio || 1;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.scale(dpr, dpr);

      // Fill background
      ctx.fillStyle = backgroundColor;
      ctx.fillRect(0, 0, width, height);
    }, [width, height, backgroundColor]);

    const getPointFromEvent = useCallback(
      (e: React.MouseEvent | React.TouchEvent | MouseEvent | TouchEvent): { x: number; y: number } => {
        const canvas = canvasRef.current;
        if (!canvas) return { x: 0, y: 0 };

        const rect = canvas.getBoundingClientRect();
        let clientX: number, clientY: number;

        if ('touches' in e) {
          const touch = e.touches[0] || e.changedTouches[0];
          clientX = touch.clientX;
          clientY = touch.clientY;
        } else {
          clientX = e.clientX;
          clientY = e.clientY;
        }

        return {
          x: clientX - rect.left,
          y: clientY - rect.top,
        };
      },
      []
    );

    const drawLine = useCallback(
      (from: { x: number; y: number }, to: { x: number; y: number }) => {
        const canvas = canvasRef.current;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.strokeStyle = penColor;
        ctx.lineWidth = penWidth;
        ctx.lineCap = 'round';
        ctx.lineJoin = 'round';
        ctx.stroke();
      },
      [penColor, penWidth]
    );

    const handleStart = useCallback(
      (e: React.MouseEvent | React.TouchEvent) => {
        e.preventDefault();
        setIsDrawing(true);
        const point = getPointFromEvent(e);
        lastPoint.current = point;

        // Draw a dot for single clicks
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        ctx.beginPath();
        ctx.arc(point.x, point.y, penWidth / 2, 0, Math.PI * 2);
        ctx.fillStyle = penColor;
        ctx.fill();

        if (isEmpty) {
          setIsEmpty(false);
          onChange?.(false);
        }
      },
      [getPointFromEvent, isEmpty, onChange, penColor, penWidth]
    );

    const handleMove = useCallback(
      (e: React.MouseEvent | React.TouchEvent) => {
        if (!isDrawing) return;
        e.preventDefault();

        const point = getPointFromEvent(e);
        if (lastPoint.current) {
          drawLine(lastPoint.current, point);
        }
        lastPoint.current = point;
      },
      [isDrawing, getPointFromEvent, drawLine]
    );

    const handleEnd = useCallback(() => {
      setIsDrawing(false);
      lastPoint.current = null;
    }, []);

    // Handle mouse leaving canvas while drawing
    useEffect(() => {
      const handleGlobalEnd = () => {
        if (isDrawing) {
          handleEnd();
        }
      };

      window.addEventListener('mouseup', handleGlobalEnd);
      window.addEventListener('touchend', handleGlobalEnd);

      return () => {
        window.removeEventListener('mouseup', handleGlobalEnd);
        window.removeEventListener('touchend', handleGlobalEnd);
      };
    }, [isDrawing, handleEnd]);

    const clear = useCallback(() => {
      const canvas = canvasRef.current;
      if (!canvas) return;

      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const dpr = window.devicePixelRatio || 1;
      ctx.fillStyle = backgroundColor;
      ctx.fillRect(0, 0, width * dpr, height * dpr);

      setIsEmpty(true);
      onChange?.(true);
    }, [backgroundColor, width, height, onChange]);

    const toDataURL = useCallback((type = 'image/png'): string => {
      const canvas = canvasRef.current;
      if (!canvas) return '';
      return canvas.toDataURL(type);
    }, []);

    // Expose methods via ref
    useImperativeHandle(
      ref,
      () => ({
        clear,
        isEmpty: () => isEmpty,
        toDataURL,
      }),
      [clear, isEmpty, toDataURL]
    );

    return (
      <div className={`signature-pad-container ${className}`}>
        <canvas
          ref={canvasRef}
          className="border border-gray-300 rounded cursor-crosshair touch-none"
          style={{ width, height }}
          onMouseDown={handleStart}
          onMouseMove={handleMove}
          onMouseUp={handleEnd}
          onMouseLeave={handleEnd}
          onTouchStart={handleStart}
          onTouchMove={handleMove}
          onTouchEnd={handleEnd}
        />
      </div>
    );
  }
);

SignaturePad.displayName = 'SignaturePad';

export default SignaturePad;
