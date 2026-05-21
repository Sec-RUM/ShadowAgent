"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Check, ChevronDown } from "lucide-react";
import type { ComponentType } from "react";
import { useEffect, useId, useRef, useState } from "react";

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

const triggerClassName =
  "group flex min-h-10 w-full items-center justify-between gap-3 rounded-md border border-[var(--field-border)] bg-[var(--field-bg)] px-3 py-2 text-left text-sm text-[var(--text-primary)] shadow-[0_16px_40px_rgba(2,6,23,0.14)] backdrop-blur-[24px] transition duration-200 hover:border-[var(--panel-border-strong)] hover:bg-[var(--field-focus-bg)] hover:shadow-[0_0_24px_rgba(45,212,191,0.08)] focus:outline-none focus:ring-2 focus:ring-teal-300/30";

const panelClassNameBase =
  "overflow-hidden rounded-[18px] border border-[var(--panel-border-strong)] bg-[var(--tooltip-bg)] p-1.5 shadow-[var(--tooltip-shadow)] backdrop-blur-[28px]";

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
  const panelId = useId();
  const rootRef = useRef<HTMLDivElement | null>(null);
  const selected = options.find((option) => option.value === value) ?? options[0];

  useEffect(() => {
    if (!open) return;

    const handlePointerDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };

    window.addEventListener("mousedown", handlePointerDown);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("mousedown", handlePointerDown);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  return (
    <div ref={rootRef} className={`relative w-full ${className}`}>
      <button
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
          className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-white/[0.08] bg-white/[0.04] text-[var(--text-secondary)] transition duration-200 group-hover:border-teal-200/18 group-hover:text-[var(--text-primary)] ${
            open ? "rotate-180 border-teal-200/26 text-[var(--text-primary)]" : ""
          }`}
        >
          <ChevronDown className="h-4 w-4" aria-hidden />
        </span>
      </button>

      <AnimatePresence initial={false}>
        {open ? (
          <motion.div
            id={panelId}
            role="listbox"
            initial={{ opacity: 0, y: 10, scale: 0.985, filter: "blur(10px)" }}
            animate={{ opacity: 1, y: 0, scale: 1, filter: "blur(0px)" }}
            exit={{ opacity: 0, y: 8, scale: 0.985, filter: "blur(8px)" }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            className={`absolute left-0 right-0 top-[calc(100%+0.55rem)] z-[80] ${panelClassNameBase} ${panelClassName}`}
          >
            <div className="pointer-events-none absolute inset-x-5 top-0 h-px bg-gradient-to-r from-transparent via-teal-200/32 to-transparent" />
            <div className="max-h-72 overflow-auto pr-1">
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
                    className={`flex w-full items-center justify-between gap-3 rounded-[14px] border px-3 py-2.5 text-left transition duration-150 ${
                      active
                        ? "border-teal-200/18 bg-white/[0.08] text-[var(--text-primary)] shadow-[0_0_26px_rgba(45,212,191,0.1)]"
                        : "border-transparent text-[var(--text-secondary)] hover:border-white/[0.08] hover:bg-white/[0.05] hover:text-[var(--text-primary)]"
                    }`}
                  >
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2">
                        {Icon ? (
                          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-white/[0.08] bg-white/[0.04]">
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
                      className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border transition ${
                        active
                          ? "border-teal-200/30 bg-teal-300/14 text-teal-100 shadow-[0_0_18px_rgba(45,212,191,0.18)]"
                          : "border-transparent text-transparent"
                      }`}
                    >
                      <Check className="h-3.5 w-3.5" aria-hidden />
                    </span>
                  </button>
                );
              })}
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}
