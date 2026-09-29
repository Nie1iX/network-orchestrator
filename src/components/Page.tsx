interface PageProps {
  width?: "narrow" | "wide" | "full";
  children: React.ReactNode;
}

export default function Page({ width = "wide", children }: PageProps) {
  return (
    <div className={`page page-${width}`}>
      {children}
    </div>
  );
}
