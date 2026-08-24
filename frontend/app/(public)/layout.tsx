
import { Navbar } from "@/components/navbar";

export default function PublicLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <>
      <Navbar />
      <main className="pt-16 md:pt-[72px] min-h-screen bg-slate-950">
        {children}
      </main>
    </>
  );
}