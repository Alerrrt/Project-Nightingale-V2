import React, { useState, useRef } from 'react';

interface PulseButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children?: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'success' | 'danger' | 'warning' | 'info' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  glowEffect?: 'none' | 'subtle' | 'intense';
  loading?: boolean;
  disabled?: boolean;
  fullWidth?: boolean;
  icon?: React.ReactNode;
  iconPosition?: 'left' | 'right';
  animationType?: 'ripple' | 'pulse' | 'glitch' | 'magnetic' | 'none';
  className?: string;
}

const cn = (...classes: (string | undefined | null | false)[]): string => {
  return classes.filter(Boolean).join(' ');
};

const PulseButton: React.FC<PulseButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  glowEffect = 'subtle',
  loading = false,
  disabled = false,
  fullWidth = false,
  icon = null,
  iconPosition = 'left',
  animationType = 'ripple',
  className = '',
  ...props
}) => {
  const [isHovered, setIsHovered] = useState(false);
  const [rippleEffect, setRippleEffect] = useState<Array<{
    x: number;
    y: number;
    size: number;
    id: number;
  }>>([]);
  const [rippleCount, setRippleCount] = useState(0);
  const buttonRef = useRef<HTMLButtonElement>(null);

  const createRipple = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (animationType !== 'ripple' || disabled || loading) return;
    const button = e.currentTarget;
    const rect = button.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const size = Math.max(rect.width, rect.height) * 2;
    const newRipple = { x, y, size, id: rippleCount };
    setRippleEffect(prev => [...prev, newRipple]);
    setRippleCount(prev => prev + 1);
    setTimeout(() => {
      setRippleEffect(prev => prev.filter(ripple => ripple.id !== newRipple.id));
    }, 1000);
  };

  const variantStyles = {
    primary: {
      background: 'bg-gradient-to-r from-blue-500 to-indigo-600',
      hover: 'hover:from-blue-600 hover:to-indigo-700',
      text: 'text-white',
      border: 'border-blue-600',
      glow: 'rgba(79, 70, 229, 0.6)',
      ripple: 'bg-blue-200 bg-opacity-30',
      loading: 'border-blue-200 border-t-blue-600',
    },
    secondary: {
      background: 'bg-gradient-to-r from-gray-700 to-gray-900',
      hover: 'hover:from-gray-800 hover:to-gray-950',
      text: 'text-gray-100',
      border: 'border-gray-600',
      glow: 'rgba(107, 114, 128, 0.6)',
      ripple: 'bg-gray-200 bg-opacity-30',
      loading: 'border-gray-400 border-t-gray-200',
    },
    success: {
      background: 'bg-gradient-to-r from-emerald-500 to-green-600',
      hover: 'hover:from-emerald-600 hover:to-green-700',
      text: 'text-white',
      border: 'border-green-600',
      glow: 'rgba(16, 185, 129, 0.6)',
      ripple: 'bg-green-200 bg-opacity-30',
      loading: 'border-green-200 border-t-green-600',
    },
    danger: {
      background: 'bg-gradient-to-r from-red-500 to-rose-600',
      hover: 'hover:from-red-600 hover:to-rose-700',
      text: 'text-white',
      border: 'border-red-600',
      glow: 'rgba(225, 29, 72, 0.6)',
      ripple: 'bg-red-200 bg-opacity-30',
      loading: 'border-red-200 border-t-red-600',
    },
    warning: {
      background: 'bg-gradient-to-r from-amber-400 to-orange-500',
      hover: 'hover:from-amber-500 hover:to-orange-600',
      text: 'text-white',
      border: 'border-amber-500',
      glow: 'rgba(251, 191, 36, 0.6)',
      ripple: 'bg-amber-200 bg-opacity-30',
      loading: 'border-amber-200 border-t-amber-500',
    },
    info: {
      background: 'bg-gradient-to-r from-cyan-500 to-sky-600',
      hover: 'hover:from-cyan-600 hover:to-sky-700',
      text: 'text-white',
      border: 'border-cyan-600',
      glow: 'rgba(6, 182, 212, 0.6)',
      ripple: 'bg-cyan-200 bg-opacity-30',
      loading: 'border-cyan-200 border-t-cyan-600',
    },
    ghost: {
      background: 'bg-transparent backdrop-blur-sm',
      hover: 'hover:bg-white hover:bg-opacity-10',
      text: 'text-white',
      border: 'border-white border-opacity-30',
      glow: 'rgba(255, 255, 255, 0.3)',
      ripple: 'bg-white bg-opacity-20',
      loading: 'border-white border-opacity-20 border-t-white',
    },
  };

  const sizeStyles = {
    sm: 'text-xs px-3 py-1.5 rounded-md',
    md: 'text-sm px-4 py-2 rounded-lg',
    lg: 'text-base px-6 py-3 rounded-xl',
  };

  const glowEffectStyles = {
    none: '',
    subtle: 'shadow-md transition-shadow duration-300',
    intense: 'shadow-lg transition-shadow duration-300',
  };

  const animationTypeStyles = {
    ripple: 'overflow-hidden transition-transform duration-200 active:scale-95',
    pulse: 'animate-pulse transition-transform duration-200 active:scale-95',
    glitch: 'transition-all duration-300 active:scale-95 glitch-effect',
    magnetic: 'transition-all duration-300',
    none: 'transition-colors duration-200 active:scale-95',
  };

  const variantStyle = variantStyles[variant];
  const sizeStyle = sizeStyles[size];
  const glowStyle = glowEffectStyles[glowEffect];
  const animationStyle = animationTypeStyles[animationType];

  return (
    <button
      ref={buttonRef}
      className={cn(
        'relative group font-medium border border-opacity-30 select-none inline-flex items-center justify-center transition-all',
        variantStyle.background,
        variantStyle.hover,
        variantStyle.text,
        variantStyle.border,
        sizeStyle,
        glowStyle,
        animationStyle,
        fullWidth ? 'w-full' : '',
        className,
        disabled ? 'opacity-50 cursor-not-allowed' : ''
      )}
      disabled={disabled || loading}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={createRipple}
      style={{
        boxShadow:
          isHovered && glowEffect !== 'none'
            ? `0 0 ${glowEffect === 'intense' ? '25px' : '15px'} ${variantStyle.glow}`
            : 'none',
      }}
      {...props}
    >
      {animationType === 'ripple' &&
        rippleEffect.map(ripple => (
          <span
            key={ripple.id}
            className={cn('absolute rounded-full', variantStyle.ripple)}
            style={{
              left: ripple.x - ripple.size / 2,
              top: ripple.y - ripple.size / 2,
              width: ripple.size,
              height: ripple.size,
              animation: 'ripple 1s ease-out forwards',
            }}
          />
        ))}

      {icon && iconPosition === 'left' && (
        <span className={cn('inline-flex', children ? 'mr-2' : '')}>{icon}</span>
      )}

      {loading ? (
        <div className="flex items-center justify-center">
          <div className={cn('animate-spin rounded-full h-4 w-4 border-2', variantStyle.loading, 'mr-2')}></div>
          {children && <span>{children}</span>}
        </div>
      ) : (
        children
      )}

      {icon && iconPosition === 'right' && (
        <span className={cn('inline-flex', children ? 'ml-2' : '')}>{icon}</span>
      )}

      <style>{`
        @keyframes ripple {
          0% {
            transform: scale(0);
            opacity: 1;
          }
          100% {
            transform: scale(1);
            opacity: 0;
          }
        }
      `}</style>
    </button>
  );
};

export default PulseButton; 