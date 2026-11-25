export default function TrafficRatio({ ratio }: { ratio?: number }) {
  return ratio == null ? null : <span className="traffic-ratio">倍率 {ratio / 1000}</span>;
}
