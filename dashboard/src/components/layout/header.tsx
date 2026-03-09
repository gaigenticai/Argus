"use client";

import { Bell, Search } from "lucide-react";

export function Header() {
  return (
    <header className="h-[72px] bg-white border-b border-[#F4F6F8] flex items-center justify-between px-6">
      <div className="flex items-center gap-3 flex-1 max-w-md">
        <Search className="w-5 h-5 text-[#919EAB]" />
        <input
          type="text"
          placeholder="Search alerts, organizations..."
          className="w-full bg-transparent text-[14px] text-[#1C252E] placeholder:text-[#919EAB] outline-none"
        />
      </div>

      <div className="flex items-center gap-4">
        <button className="relative p-2 rounded-lg hover:bg-[#F4F6F8] transition-colors">
          <Bell className="w-5 h-5 text-[#637381]" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-[#FF5630] rounded-full" />
        </button>
        <div className="w-9 h-9 rounded-full bg-[#00A76F] flex items-center justify-center text-white text-[14px] font-bold">
          A
        </div>
      </div>
    </header>
  );
}
