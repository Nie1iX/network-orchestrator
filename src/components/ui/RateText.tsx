import { ArrowDownIcon, ArrowUpIcon } from "../../icons";
import { formatRate } from "../../format";

interface RateTextProps {
  rx: number;
  tx: number;
  live?: boolean;
}

/** Inline "↓ rx · ↑ tx" readout with real vector icons, tabular numerals. */
export default function RateText({ rx, tx, live }: RateTextProps) {
  return (
    <span className={`rate-pair ${live ? "live" : ""}`}>
      <span className="rate-dir">
        <ArrowDownIcon size={12} />
        {formatRate(rx)}
      </span>
      <span className="rate-dir">
        <ArrowUpIcon size={12} />
        {formatRate(tx)}
      </span>
    </span>
  );
}
