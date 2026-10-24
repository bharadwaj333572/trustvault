import React from 'react';

export function TrustVaultLogo({ className = 'h-7 w-auto' }: { className?: string }) {
  return (
    <div className={`flex items-center gap-2.5 font-display tracking-tight font-black select-none ${className}`}>
      <svg
        width="28"
        height="28"
        viewBox="0 0 28 28"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="flex-shrink-0"
      >
        {/* Hexagonal Vault Shackle */}
        <path
          d="M14 2L25 8.5V19.5L14 26L3 19.5V8.5L14 2Z"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinejoin="round"
        />
        {/* Central Core Hash Link */}
        <rect
          x="9"
          y="9"
          width="10"
          height="10"
          rx="2"
          fill="#FF5A1F"
        />
        {/* Lock pin hole */}
        <circle cx="14" cy="14" r="2" fill="#0B1220" />
      </svg>
      <div className="flex flex-col leading-none">
        <span className="text-[17px] tracking-wider uppercase font-extrabold text-current">
          TRUST<span className="text-accent">VAULT</span>
        </span>
        <span className="text-[8px] font-mono tracking-[0.25em] text-accent font-semibold uppercase mt-0.5">
          VERIFIED VAULT
        </span>
      </div>
    </div>
  );
}
