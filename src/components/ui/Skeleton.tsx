interface SkeletonProps {
  width?: string;
  height?: string;
  radius?: string;
  className?: string;
}

export default function Skeleton({
  width = "100%",
  height = "1rem",
  radius,
  className,
}: SkeletonProps) {
  return (
    <span
      className={`skeleton ${className ?? ""}`}
      style={{ width, height, borderRadius: radius }}
    />
  );
}
