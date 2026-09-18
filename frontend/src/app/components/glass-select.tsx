"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Check, ChevronDown } from "lucide-react";
import type { ComponentType } from "react";
import { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

type IconLike = ComponentType<{
  className?: string;
  "aria-hidden"?: boolean;
}>;

export type GlassSelectOption = {
  value: string;
  label: string;
  description?: string;
  icon?: IconLike;
};

type GlassSelectProps = {
  value: string;
  options: GlassSelectOption[];
  onChange: (value: string) => void;
  ariaLabel: string;
  className?: string;
  buttonClassName?: string;
  panelClassName?: string;
};

type DropdownPosition = {
  bottom?: number;
  left: number;
  maxHeight: number;
  placement: "top" | "bottom";
  top?: number;
  width: number;
};

const triggerClassName =
  "group flex min-h-10 w-full items-center justify-between gap-3 rounded-xl border border-[var(--field-border)] bg-[var(--field-bg)] px-3.5 py-2 text-left text-sm text-[var(--text-primary)] shadow-[0_10px_30px_rgba(2,6,23,0.06)] backdrop-blur-[24px] transition-all duration-200 ease-out hover:border-[var(--panel-border-strong)] hover:bg-[var(--field-focus-bg)] hover:shadow-[0_0_24px_rgba(45,212,191,0.1)] focus:outline-none focus:ring-2 focus:ring-teal-300/40 active:scale-[0.99]";

const panelClassNameBase =
  "overflow-hidden rounded-2xl border border-[color:var(--tooltip-border)] bg-[color:var(--tooltip-bg)] p-1.5 shadow-[var(--tooltip-shadow)] ring-1 ring-white/15 backdrop-blur-[32px]";

export function GlassSelect({
  value,
  options,
  onChange,
  ariaLabel,
  className = "",
  buttonClassName = "",
  panelClassName = "",
}: GlassSelectProps) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState<DropdownPosition | null>(null);
  const panelId = useId();
  const panelRef = useRef<HTMLDivElement | null>(null);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const selected = options.find((option) => option.value === value) ?? options[0];
  const activePosition = open ? position : null;

  useEffect(() => {
    if (!open) return;

    const updatePosition = () => {
      const trigger = triggerRef.current;
      if (!trigger) return;

      const rect = trigger.getBoundingClientRect();
      const viewportPadding = 12;
      const gap = 10;
      const availableBelow = window.innerHeight - rect.bottom - viewportPadding - gap;
      const availableAbove = rect.top - viewportPadding - gap;
      const shouldOpenUpward = availableBelow < 220 && availableAbove > availableBelow;
      const availableSpace = shouldOpenUpward ? availableAbove : availableBelow;
      const width = Math.min(rect.width, window.innerWidth - viewportPadding * 2);
      const left = Math.min(
        Math.max(rect.left, viewportPadding),
        window.innerWidth - width - viewportPadding
      );

      setPosition(
        shouldOpenUpward
          ? {
              left,
              width,
              bottom: window.innerHeight - rect.top + gap,
              maxHeight: Math.max(96, Math.min(320, availableSpace)),
              placement: "top",
            }
          : {
              left,
              width,
              top: rect.bottom + gap,
              maxHeight: Math.max(96, Math.min(320, availableSpace)),
              placement: "bottom",
            }
      );
    };

    updatePosition();

    const handlePointerDown = (event: MouseEvent) => {
      const target = event.target as Node;
      if (!rootRef.current?.contains(target) && !panelRef.current?.contains(target)) {
        setOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };

    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    window.addEventListener("mousedown", handlePointerDown);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
      window.removeEventListener("mousedown", handlePointerDown);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  const panel =
    activePosition
      ? createPortal(
          <AnimatePresence initial={false}>
            <motion.div
              ref={panelRef}
              id={panelId}
              role="listbox"
              initial={{
                opacity: 0,
                y: activePosition.placement === "bottom" ? 6 : -6,
                scale: 0.985,
              }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{
                opacity: 0,
                y: activePosition.placement === "bottom" ? 4 : -4,
                scale: 0.985,
              }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              style={{
                left: activePosition.left,
                width: activePosition.width,
                maxHeight: activePosition.maxHeight,
                top: activePosition.top,
                bottom: activePosition.bottom,
                transformOrigin: activePosition.placement === "bottom" ? "top center" : "bottom center",
              }}
              className={`fixed z-[240] ${panelClassNameBase} ${panelClassName}`}
            >
              <div className="pointer-events-none absolute inset-x-5 top-0 h-px bg-gradient-to-r from-transparent via-teal-200/32 to-transparent" />
              <div className="max-h-full overflow-auto pr-1">
                {options.map((option) => {
                  const Icon = option.icon;
                  const active = option.value === value;

                  return (
                    <button
                      key={option.value}
                      type="button"
                      role="option"
                      aria-selected={active}
                      onClick={() => {
                        onChange(option.value);
                        setOpen(false);
                      }}
                      className={`flex w-full items-center justify-between gap-3 rounded-xl border px-3 py-2 text-left transition-all duration-150 ease-out ${
                        active
                          ? "border-teal-200/30 bg-teal-300/[0.12] text-[color:var(--tooltip-fg)] shadow-[0_0_20px_rgba(45,212,191,0.1)]"
                          : "border-transparent bg-transparent text-[color:var(--tooltip-fg)] opacity-85 hover:border-white/[0.08] hover:bg-white/[0.07] hover:opacity-100"
                      }`}
                    >
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-2">
                          {Icon ? (
                            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.04]">
                              <Icon className="h-4 w-4" aria-hidden />
                            </span>
                          ) : null}
                          <span className="truncate text-sm font-medium">{option.label}</span>
                        </span>
                        {option.description ? (
                          <span className={`mt-1 block truncate text-[11px] text-[var(--text-secondary)] ${Icon ? "pl-9" : ""}`}>{option.description}</span>
                        ) : null}
                      </span>
                      <span
                        className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border transition-all duration-200 ${
                          active
                            ? "border-teal-200/30 bg-teal-300/14 text-teal-100 shadow-[0_0_18px_rgba(45,212,191,0.18)] scale-100"
                            : "border-transparent text-transparent scale-75"
                        }`}
                      >
                        <Check className="h-3.5 w-3.5" aria-hidden />
                      </span>
                    </button>
                  );
                })}
              </div>
            </motion.div>
          </AnimatePresence>,
          document.body
        )
      : null;

  return (
    <div ref={rootRef} className={`relative w-full ${className}`}>
      <button
        ref={triggerRef}
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((current) => !current)}
        className={`${triggerClassName} ${buttonClassName}`}
      >
        <span className="min-w-0 flex-1">
          <span className="block truncate font-medium">{selected?.label ?? "-"}</span>
          {selected?.description ? (
            <span className="mt-0.5 block truncate text-[11px] text-[var(--text-secondary)]">{selected.description}</span>
          ) : null}
        </span>
        <span
          className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.04] text-[var(--text-secondary)] transition-all duration-200 ease-out group-hover:border-teal-200/25 group-hover:text-[var(--text-primary)] ${
            open ? "rotate-180 border-teal-200/30 text-[var(--text-primary)]" : ""
          }`}
        >
          <ChevronDown className="h-4 w-4" aria-hidden />
        </span>
      </button>
      {panel}
    </div>
  );
}
