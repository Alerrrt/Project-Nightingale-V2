import { cn } from "../../lib/utils";
import { motion } from "framer-motion";

const Skeleton = ({ className, ...props }) => {
  return (
    <motion.div
      className={cn(
        "animate-pulse rounded-md bg-muted",
        className
      )}
      initial={{ opacity: 0.5 }}
      animate={{ opacity: 1 }}
      transition={{
        duration: 1,
        repeat: Infinity,
        repeatType: "reverse",
      }}
      {...props}
    />
  );
};

export { Skeleton }; 