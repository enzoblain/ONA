import type { ReactNode } from "react";
import { motion } from "motion/react";
import { EASE } from "./Layout";

type Tag = "div" | "article" | "ul" | "p";

// Rises 32px and fades in, once, when it enters the viewport.
export function Reveal({ children, className, delay = 0, tag = "div" }: {
  children: ReactNode;
  className?: string;
  delay?: number;
  tag?: Tag;
}) {
  const Component = motion[tag] as typeof motion.div;
  return (
    <Component
      className={className}
      initial={{ opacity: 0, y: 32 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "0px 0px -8% 0px" }}
      transition={{ duration: 0.7, ease: EASE, delay }}
    >
      {children}
    </Component>
  );
}
