import React from 'react';

interface HospitalHuaralLogoProps {
  className?: string;
}

export const HospitalHuaralLogo: React.FC<HospitalHuaralLogoProps> = ({ className = 'w-20 h-20' }) => {
  return (
    <svg
      viewBox="0 0 240 260"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="Escudo Hospital San Juan Bautista Huaral"
    >
      {/* White background fill inside the oval */}
      <ellipse cx="120" cy="130" rx="96" ry="116" fill="#FFFFFF" stroke="#0082C8" strokeWidth="8" />

      {/* Left and Right curved ribs inside the oval */}
      <path
        d="M52 46 C 85 95, 85 165, 52 214"
        stroke="#0082C8"
        strokeWidth="7"
        strokeLinecap="round"
        fill="none"
      />
      <path
        d="M188 46 C 155 95, 155 165, 188 214"
        stroke="#0082C8"
        strokeWidth="7"
        strokeLinecap="round"
        fill="none"
      />

      {/* Inner shield frame connecting top and bottom boxes */}
      <path
        d="M78 74 C 92 74, 96 86, 96 96 L 96 164 C 96 174, 92 186, 78 186"
        stroke="#0082C8"
        strokeWidth="6"
        fill="none"
      />
      <path
        d="M162 74 C 148 74, 144 86, 144 96 L 144 164 C 144 174, 148 186, 162 186"
        stroke="#0082C8"
        strokeWidth="6"
        fill="none"
      />

      {/* Top Box: HOSPITAL */}
      <rect x="66" y="38" width="108" height="36" fill="#FFFFFF" stroke="#0082C8" strokeWidth="7" />
      <text
        x="120"
        y="62"
        textAnchor="middle"
        fill="#111827"
        fontFamily="Arial, Helvetica, sans-serif"
        fontWeight="900"
        fontSize="18"
        letterSpacing="0.5"
      >
        HOSPITAL
      </text>

      {/* Bottom Box: HUARAL */}
      <rect x="66" y="186" width="108" height="36" fill="#FFFFFF" stroke="#0082C8" strokeWidth="7" />
      <text
        x="120"
        y="210"
        textAnchor="middle"
        fill="#111827"
        fontFamily="Arial, Helvetica, sans-serif"
        fontWeight="900"
        fontSize="18"
        letterSpacing="1"
      >
        HUARAL
      </text>

      {/* Golden Caduceus Wings */}
      <path
        d="M120 104 C 98 90, 74 92, 66 104 C 76 112, 96 114, 120 112 Z"
        fill="#D4AF37"
        stroke="#9A7B1C"
        strokeWidth="2"
      />
      <path
        d="M120 104 C 142 90, 166 92, 174 104 C 164 112, 144 114, 120 112 Z"
        fill="#D4AF37"
        stroke="#9A7B1C"
        strokeWidth="2"
      />

      {/* Golden Caduceus Rod & Top Orb */}
      <line x1="120" y1="84" x2="120" y2="178" stroke="#B8860B" strokeWidth="5" strokeLinecap="round" />
      <circle cx="120" cy="82" r="8" fill="#EAB308" stroke="#9A7B1C" strokeWidth="2.5" />

      {/* Intertwined Serpents */}
      <path
        d="M108 108 C 132 118, 106 136, 130 148 C 114 158, 114 168, 124 174"
        stroke="#CA8A04"
        strokeWidth="3.5"
        fill="none"
        strokeLinecap="round"
      />
      <path
        d="M132 108 C 108 118, 134 136, 110 148 C 126 158, 126 168, 116 174"
        stroke="#CA8A04"
        strokeWidth="3.5"
        fill="none"
        strokeLinecap="round"
      />

      {/* Center Initials: SJB */}
      <text
        x="120"
        y="152"
        textAnchor="middle"
        fill="#0F172A"
        fontFamily="Georgia, 'Times New Roman', serif"
        fontWeight="bold"
        fontSize="48"
        letterSpacing="1"
      >
        SJB
      </text>
    </svg>
  );
};
