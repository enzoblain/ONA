import Scanner from "./reactbits/Scanner";

// The React Bits scanner, in greys and very faint, as a backdrop: behind a section, or (`page`) behind a whole page.
// It is decoration only: no pointer interaction, and it stops when it is off screen.
export function ScannerBackdrop({ page = false }: { page?: boolean }) {
  return (
    <div className={page ? "scanner-bg scanner-page" : "scanner-bg"} aria-hidden="true">
      <Scanner color1="#ffffff" color2="#9a9ca3" color3="#55575d" speed={0.6} sweepSpeed={0.5} mouseInteraction={false} clickEffect="none" intro={false} />
    </div>
  );
}
