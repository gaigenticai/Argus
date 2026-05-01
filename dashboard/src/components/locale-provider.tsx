"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

import { api, type LocaleResponse } from "@/lib/api";
import {
  type AppLocale,
  type CalendarSystem,
  getDefaultLocale,
  setDefaultLocale,
} from "@/lib/utils";

interface LocaleContextValue {
  locale: AppLocale;
  /** List of TZ identifiers + calendar codes the picker exposes. */
  supported: { timezones: readonly string[]; calendars: readonly CalendarSystem[] };
  /** Persist a new locale to the server. Local module-default updates
   *  synchronously so date strings re-render with the new format on
   *  the next React tick. */
  setLocale: (next: Partial<AppLocale>) => Promise<void>;
}

const LocaleContext = createContext<LocaleContextValue | null>(null);

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<AppLocale>(getDefaultLocale());
  const [supported, setSupported] = useState<{
    timezones: readonly string[];
    calendars: readonly CalendarSystem[];
  }>({
    timezones: ["Asia/Riyadh", "UTC"],
    calendars: ["gregorian", "islamic-umalqura"],
  });

  useEffect(() => {
    let active = true;
    api.organizations
      .getLocale()
      .then((r: LocaleResponse) => {
        if (!active) return;
        const next: AppLocale = {
          timeZone: r.timezone,
          calendar: r.calendar_system as CalendarSystem,
        };
        setLocaleState(next);
        setDefaultLocale(next);
        setSupported({
          timezones: r.supported.timezones,
          calendars: r.supported.calendars as readonly CalendarSystem[],
        });
      })
      .catch(() => {
        // Fallback to GCC default — set in utils.ts module-level.
      });
    return () => {
      active = false;
    };
  }, []);

  async function setLocale(next: Partial<AppLocale>) {
    const merged = { ...locale, ...next };
    await api.organizations.updateLocale({
      timezone: merged.timeZone,
      calendar_system: merged.calendar,
    });
    setLocaleState(merged);
    setDefaultLocale(merged);
  }

  return (
    <LocaleContext.Provider value={{ locale, supported, setLocale }}>
      {children}
    </LocaleContext.Provider>
  );
}

export function useLocale(): LocaleContextValue {
  const ctx = useContext(LocaleContext);
  if (ctx === null) {
    throw new Error("useLocale must be used inside <LocaleProvider>");
  }
  return ctx;
}
