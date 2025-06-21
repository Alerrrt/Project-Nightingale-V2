import React from 'react';

interface CircleProgressProps {
  value: number;
  maxValue: number;
  size?: number;
  strokeWidth?: number;
  className?: string;
}

const cn = (...classes: (string | undefined | null | false)[]): string => {
  return classes.filter(Boolean).join(' ');
};

const CircleProgress: React.FC<CircleProgressProps> = ({
  value,
  maxValue,
  size = 40,
  strokeWidth = 3,
  className,
}) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const fillPercentage = Math.min(value / maxValue, 1);
  const strokeDashoffset = circumference * (1 - fillPercentage);

  const getColor = (percentage: number) => {
    if (percentage < 0.7) return 'stroke-emerald-500';
    if (percentage < 0.9) return 'stroke-amber-500';
    return 'stroke-red-500';
  };

  const currentColor = getColor(fillPercentage);

  return (
    <div className={cn(className)}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          className="fill-transparent stroke-gray-200 dark:stroke-gray-700"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          className={cn('fill-transparent transition-colors', currentColor)}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          strokeLinecap="round"
        />
      </svg>
    </div>
  );
};

export default CircleProgress; 