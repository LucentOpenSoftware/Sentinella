/**
 * Custom Sentinella shield icons — individual PNGs extracted from sprite sheet.
 */

import iconSentinel from "../assets/icons/sentinel.png";
import iconSentinelAlt from "../assets/icons/sentinelAlt.png";
import iconScan from "../assets/icons/scan.png";
import iconThreat from "../assets/icons/threat.png";
import iconQuarantine from "../assets/icons/quarantine.png";
import iconProtected from "../assets/icons/protected.png";
import iconFileWarning from "../assets/icons/file_warning.png";
import iconAlert from "../assets/icons/alert.png";

const ICONS = {
  sentinel: iconSentinel,
  sentinelAlt: iconSentinelAlt,
  scan: iconScan,
  threat: iconThreat,
  quarantine: iconQuarantine,
  protected: iconProtected,
  fileWarning: iconFileWarning,
  alert: iconAlert,
} as const;

export type ShieldPreset = keyof typeof ICONS;

interface Props {
  icon: ShieldPreset;
  size?: number;
  className?: string;
}

export function ShieldIcon({ icon, size = 24, className = "" }: Props) {
  return (
    <img
      src={ICONS[icon]}
      alt=""
      draggable={false}
      aria-hidden="true"
      className={`flex-shrink-0 ${className}`}
      style={{ width: size, height: size, objectFit: "contain" }}
    />
  );
}
